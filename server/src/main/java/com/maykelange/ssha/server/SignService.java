package com.maykelange.ssha.server;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.TimeUnit;

import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

/**
 * Relays SSH sign requests from the CLI agent to the phone and the phone's signatures back. The
 * server never holds a private key: it only shows what is being signed and checks the returned
 * signature against the public key before passing it on.
 */
@Service
public class SignService {

    /** Most SSH sign payloads are a few hundred bytes; SSHSIG signs a hash, not the message. */
    public static final int MAX_DATA_LENGTH = 16 * 1024;

    /** Most requests one computer may have waiting: ssh asks one at a time per connection. */
    static final int MAX_PENDING_PER_CLIENT = 2;
    /** Most requests one account may have waiting, from all its computers. */
    static final int MAX_PENDING_PER_ACCOUNT = 5;

    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * OpenSSH's {@code session-bind@openssh.com}: the server's host key and its signature over the
     * session id, which proves which host a login is for.
     */
    public record Binding(byte[] hostKey, byte[] sessionId, byte[] signature, boolean forwarded) {
    }

    /**
     * @param algorithm  SSH signature algorithm, e.g. ssh-ed25519 or rsa-sha2-512
     * @param client     the computer asking, as stored when it joined
     * @param host       earlier logins to this (verified) host; null if none, or not a verified login
     * @param concurrent whether other requests of the account were waiting when this one came in
     */
    public record Pending(String id, SshKey key, byte[] data, String algorithm, SignDetails details,
                          Accounts.Client client, KnownHosts.Seen host, boolean concurrent, Instant requestedAt,
                          CompletableFuture<byte[]> result) {

        /** A verified login to a host the account never approved a login to. */
        public boolean newHost() {
            return details.hostVerified() && host == null;
        }

        /** The bytes to sign, for the phone. */
        public String payload() {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
        }

        /** The WebCrypto hash for RSA signatures; null for Ed25519. */
        public String hash() {
            return switch (algorithm) {
                case "rsa-sha2-512" -> "SHA-512";
                case "rsa-sha2-256" -> "SHA-256";
                default -> null;
            };
        }
    }

    /** The request was denied on the phone. */
    public static final class DeniedException extends RuntimeException {
        DeniedException() {
            super("denied on the phone", null, false, false);
        }
    }

    private final Map<String, Pending> pending = new ConcurrentHashMap<>();
    private final StreamHub streams;
    private final TemplateEngine templates;
    private final SshaProperties props;
    private final PushService push;
    private final KnownHosts knownHosts;
    private final RateLimits limits;
    private final ActivityLog activity;

    public SignService(StreamHub streams, TemplateEngine templates, SshaProperties props, PushService push,
                       KnownHosts knownHosts, RateLimits limits, ActivityLog activity) {
        this.streams = streams;
        this.templates = templates;
        this.props = props;
        this.push = push;
        this.knownHosts = knownHosts;
        this.limits = limits;
        this.activity = activity;
        // A page that (re)connects gets every request of its account that is still waiting.
        streams.onConnect((account, emitter) -> pending(account).forEach(p -> streams.send(emitter, "sign", render(p))));
    }

    /**
     * Shows the request on the phone. The future completes with an SSH signature blob, or fails with
     * {@link DeniedException}, a {@link java.util.concurrent.TimeoutException}, or a cancellation.
     *
     * @param flags  ssh-agent sign flags (they pick the RSA hash)
     * @param client the computer asking; it must belong to the key's account
     * @throws IllegalArgumentException for signatures the phone won't make (SHA-1 RSA)
     * @throws IllegalStateException    if the computer or account has too many requests waiting, or the
     *                                  computer sent too many lately
     */
    public synchronized CompletableFuture<byte[]> request(SshKey key, byte[] data, int flags, Binding binding,
                                                          Accounts.Client client) {
        if (!client.accountId().equals(key.accountId())) {
            throw new IllegalArgumentException("the key belongs to another account");
        }
        String algorithm = SshWire.signatureAlgorithm(key.publicKey(), flags);
        List<Pending> waiting = pending(key.accountId());
        if (waiting.size() >= MAX_PENDING_PER_ACCOUNT
                || waiting.stream().filter(w -> w.client().id().equals(client.id())).count() >= MAX_PENDING_PER_CLIENT) {
            throw new IllegalStateException("too many sign requests waiting on the phone");
        }
        if (!limits.signsPerClient.tryAcquire(client.id())) {
            throw new IllegalStateException("too many sign requests from this computer; wait a minute");
        }
        SignDetails details = SignDetails.describe(key.publicKey(), data, binding);
        KnownHosts.Seen host = details.hostVerified()
                ? knownHosts.find(key.accountId(), details.hostKey()).orElse(null)
                : null;
        byte[] id = new byte[16];
        RANDOM.nextBytes(id);
        Pending p = new Pending(Base64.getUrlEncoder().withoutPadding().encodeToString(id), key, data.clone(),
                algorithm, details, client, host, !waiting.isEmpty(), Instant.now(), new CompletableFuture<>());
        pending.put(p.id(), p);
        p.result().orTimeout(props.signTimeout().toMillis(), TimeUnit.MILLISECONDS).whenComplete((sig, err) -> {
            pending.remove(p.id());
            logOutcome(p, err);
            streams.broadcast(key.accountId(), "sign", "<div id=\"sign-" + p.id() + "\" hx-swap-oob=\"delete\"></div>");
        });
        streams.broadcast(key.accountId(), "sign", render(p));
        push.notify(key.accountId(), notification(p));
        return p.result();
    }

    /** @param signature the raw signature made on the phone (Ed25519, or RSASSA-PKCS1-v1_5) */
    public void approve(String accountId, String id, byte[] signature) {
        Pending p = find(accountId, id);
        byte[] blob = SshWire.signatureBlob(p.algorithm(), signature);
        if (!SshWire.verify(p.key().publicKey(), p.data(), blob)) {
            throw new IllegalArgumentException("the signature does not match the key");
        }
        if (p.result().complete(blob) && p.details().hostVerified()) {
            knownHosts.login(accountId, p.details().hostKey());
        }
    }

    public void deny(String accountId, String id) {
        find(accountId, id).result().completeExceptionally(new DeniedException());
    }

    public List<Pending> pending(String accountId) {
        return pending.values().stream()
                .filter(p -> p.key().accountId().equals(accountId))
                .sorted(Comparator.comparing(Pending::requestedAt))
                .toList();
    }

    /** Another account's request is as unknown as a missing one. */
    private Pending find(String accountId, String id) {
        Pending p = pending.get(id);
        if (p == null || !p.key().accountId().equals(accountId)) {
            throw new NoSuchElementException("no such request (answered or expired)");
        }
        return p;
    }

    private void logOutcome(Pending p, Throwable err) {
        String event = err == null ? "approved"
                : err instanceof DeniedException ? "denied"
                : err instanceof TimeoutException ? "expired"
                : "cancelled";
        SignDetails d = p.details();
        StringBuilder detail = new StringBuilder(d.kind());
        if (d.user() != null) {
            detail.append(" as ").append(d.user());
        }
        if (d.hostKey() != null) {
            detail.append(" on ").append(d.hostKey()).append(d.hostVerified() ? "" : " (unverified)");
        }
        if (d.namespace() != null) {
            detail.append(" (").append(d.namespace()).append(')');
        }
        if (d.forwarded()) {
            detail.append(", forwarded agent");
        }
        detail.append(" with key ").append(p.key().label());
        activity.record(p.key().accountId(), ActivityLog.SIGN, event, detail.toString(), p.client().name());
    }

    private PushService.Notification notification(Pending p) {
        SignDetails d = p.details();
        StringBuilder body = new StringBuilder(p.client().name()).append(" wants to use key ").append(p.key().label());
        if (d.user() != null) {
            body.append(" as ").append(d.user());
        }
        if (p.newHost()) {
            body.append(" on a host you never logged in to");
        }
        if (d.namespace() != null) {
            body.append(" (").append(d.namespace()).append(')');
        }
        if (d.warning() != null) {
            body.append(". ").append(d.warning());
        }
        if (p.concurrent()) {
            body.append(". Other requests are waiting too: check that each one is yours.");
        }
        return new PushService.Notification(d.kind(), body.toString(), "sign-" + p.id(), props.signTimeout());
    }

    private String render(Pending p) {
        Context ctx = new Context();
        ctx.setVariable("p", p);
        // Newlines would split the SSE data field into several lines.
        return templates.process("fragments/sign", Set.of("sign"), ctx).replace('\n', ' ');
    }
}
