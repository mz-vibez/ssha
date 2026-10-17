package com.maykelange.ssha.server.vault;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import com.maykelange.ssha.server.SshaProperties;
import com.maykelange.ssha.server.account.Accounts;
import com.maykelange.ssha.server.push.PushService;
import com.maykelange.ssha.server.security.Passkeys;
import com.maykelange.ssha.server.ssh.SignService;
import com.maykelange.ssha.server.web.StreamHub;

/**
 * Devices asking for the account's vault key: a passkey without a slot (a new phone, a hardware key)
 * sends an ECDH public key, and a device that has the vault key encrypts it to that key. The server
 * only relays; it never holds anything that opens the vault. Both screens show a code derived from
 * the public key, so the user can tell their own device's request from one the server made up.
 */
@Service
public class VaultJoins {

    /** Most requests one account may have waiting. */
    static final int MAX_PENDING_PER_ACCOUNT = 3;

    /** ECDH P-256 public keys, uncompressed: 0x04, x, y. */
    static final int PUBLIC_KEY_LENGTH = 65;

    /**
     * The vault key, encrypted to the asking device: AES-GCM under a key derived from ECDH between
     * {@code ephemeralKey} and the device's public key.
     */
    public record Grant(byte[] ephemeralKey, byte[] iv, byte[] data) {
    }

    /**
     * @param credentialId the asking device's passkey, base64url
     * @param publicKey    the asking device's ECDH P-256 public key, uncompressed
     * @param code         derived from {@code publicKey}; both devices compute it themselves
     * @param device       address and user agent of the asking browser
     */
    public record Pending(String id, String accountId, String credentialId, byte[] publicKey, String code,
                          String device, Instant requestedAt, CompletableFuture<Grant> result) {

        public String publicKeyBase64() {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey);
        }
    }

    private final Map<String, Pending> pending = new ConcurrentHashMap<>();
    private final Passkeys passkeys;
    private final VaultSlots slots;
    private final StreamHub streams;
    private final TemplateEngine templates;
    private final SshaProperties props;
    private final PushService push;

    public VaultJoins(Passkeys passkeys, VaultSlots slots, StreamHub streams, TemplateEngine templates,
                      SshaProperties props, PushService push) {
        this.passkeys = passkeys;
        this.slots = slots;
        this.streams = streams;
        this.templates = templates;
        this.props = props;
        this.push = push;
        streams.onConnect((account, emitter) -> waiting(account).forEach(p -> streams.send(emitter, "sign", render(p))));
    }

    /**
     * Shows the request on the account's other devices. Its result completes with the grant, or fails
     * with {@link SignService.DeniedException}, a {@link java.util.concurrent.TimeoutException}, or a
     * cancellation; the asking device polls for it with {@link #find}.
     *
     * @throws IllegalArgumentException if {@code publicKey} isn't an uncompressed P-256 point
     * @throws NoSuchElementException   if the passkey isn't one of the account's
     * @throws IllegalStateException    if the passkey can open the vault already, there is no vault to
     *                                  share, or too many requests are waiting
     */
    public synchronized Pending request(String accountId, Bytes credentialId, byte[] publicKey, String device) {
        if (publicKey == null || publicKey.length != PUBLIC_KEY_LENGTH || publicKey[0] != 4) {
            throw new IllegalArgumentException("invalid public key");
        }
        if (!passkeys.owns(accountId, credentialId)) {
            throw new NoSuchElementException("not a passkey of this account");
        }
        if (!slots.exists(accountId)) {
            throw new IllegalStateException("the account has no synced SSH keys yet");
        }
        if (slots.has(accountId, credentialId)) {
            throw new IllegalStateException("this passkey can open the vault already");
        }
        if (waiting(accountId).size() >= MAX_PENDING_PER_ACCOUNT) {
            throw new IllegalStateException("too many devices waiting for this account");
        }
        Pending p = new Pending(Accounts.randomId(16), accountId, credentialId.toBase64UrlString(), publicKey,
                code(publicKey), device, Instant.now(), new CompletableFuture<>());
        pending.put(p.id(), p);
        p.result().orTimeout(props.deviceTimeout().toMillis(), TimeUnit.MILLISECONDS).whenComplete((grant, error) ->
                streams.broadcast(accountId, "sign", "<div id=\"device-" + p.id() + "\" data-remove></div>"));
        streams.broadcast(accountId, "sign", render(p));
        push.notify(accountId, new PushService.Notification("New device",
                "A device asks for your SSH keys, code " + p.code(), "device-" + p.id(), props.deviceTimeout()));
        return p;
    }

    /** @throws NoSuchElementException if there is no such request (or it is long gone) */
    public Pending find(String accountId, String id) {
        Pending p = pending.get(id);
        if (p == null || !p.accountId().equals(accountId)) {
            throw new NoSuchElementException("no such request (answered or expired)");
        }
        return p;
    }

    /** Hands the encrypted vault key to the asking device. Repeating it changes nothing. */
    public void approve(String accountId, String id, Grant grant) {
        if (grant.ephemeralKey() == null || grant.ephemeralKey().length != PUBLIC_KEY_LENGTH
                || grant.iv() == null || grant.iv().length != 12
                || grant.data() == null || grant.data().length != 32 + 16) {
            throw new IllegalArgumentException("invalid grant");
        }
        Pending p = find(accountId, id);
        if (!p.result().complete(grant) && p.result().isCompletedExceptionally()) {
            throw new NoSuchElementException("no such request (answered or expired)");
        }
    }

    public void deny(String accountId, String id) {
        find(accountId, id).result().completeExceptionally(new SignService.DeniedException());
    }

    /** The passkey has its slot now: its requests are done with. */
    public void joined(String accountId, Bytes credentialId) {
        String id = credentialId.toBase64UrlString();
        pending.values().removeIf(p -> p.accountId().equals(accountId) && p.credentialId().equals(id));
    }

    /** Requests no device has answered yet, oldest first. */
    public List<Pending> waiting(String accountId) {
        return pending.values().stream()
                .filter(p -> p.accountId().equals(accountId) && !p.result().isDone())
                .sorted(Comparator.comparing(Pending::requestedAt))
                .toList();
    }

    /** Answered requests stay a while for the asking device to collect the answer. */
    @Scheduled(fixedRate = 60_000)
    public void cleanUp() {
        Instant cutoff = Instant.now().minus(props.deviceTimeout().multipliedBy(2));
        pending.values().removeIf(p -> p.requestedAt().isBefore(cutoff));
    }

    /** Six digits from the SHA-256 of the public key, as ssh.js computes them: "123 456". */
    static String code(byte[] publicKey) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(publicKey);
            long n = Integer.toUnsignedLong(ByteBuffer.wrap(hash).getInt()) % 1_000_000;
            String digits = String.format("%06d", n);
            return digits.substring(0, 3) + " " + digits.substring(3);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private String render(Pending p) {
        Context ctx = new Context();
        ctx.setVariable("p", p);
        return templates.process("fragments/device", Set.of("device"), ctx).replace('\n', ' ');
    }
}
