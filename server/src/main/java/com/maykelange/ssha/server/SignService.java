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

    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * OpenSSH's {@code session-bind@openssh.com}: the server's host key and its signature over the
     * session id, which proves which host a login is for.
     */
    public record Binding(byte[] hostKey, byte[] sessionId, byte[] signature, boolean forwarded) {
    }

    /** @param algorithm SSH signature algorithm, e.g. ssh-ed25519 or rsa-sha2-512 */
    public record Pending(String id, SshKey key, byte[] data, String algorithm, SignDetails details, String client,
                          Instant requestedAt, CompletableFuture<byte[]> result) {

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

    public SignService(StreamHub streams, TemplateEngine templates, SshaProperties props) {
        this.streams = streams;
        this.templates = templates;
        this.props = props;
        // A page that (re)connects gets every request that is still waiting.
        streams.onConnect(emitter -> pending().forEach(p -> streams.send(emitter, "sign", render(p))));
    }

    /**
     * Shows the request on the phone. The future completes with an SSH signature blob, or fails with
     * {@link DeniedException}, a {@link java.util.concurrent.TimeoutException}, or a cancellation.
     *
     * @param flags ssh-agent sign flags (they pick the RSA hash)
     * @throws IllegalArgumentException for signatures the phone won't make (SHA-1 RSA)
     */
    public CompletableFuture<byte[]> request(SshKey key, byte[] data, int flags, Binding binding, String client) {
        String algorithm = SshWire.signatureAlgorithm(key.publicKey(), flags);
        byte[] id = new byte[16];
        RANDOM.nextBytes(id);
        Pending p = new Pending(Base64.getUrlEncoder().withoutPadding().encodeToString(id), key, data.clone(),
                algorithm, SignDetails.describe(key.publicKey(), data, binding), client, Instant.now(), new CompletableFuture<>());
        pending.put(p.id(), p);
        p.result().orTimeout(props.signTimeout().toMillis(), TimeUnit.MILLISECONDS).whenComplete((sig, err) -> {
            pending.remove(p.id());
            streams.broadcast("sign", "<div id=\"sign-" + p.id() + "\" hx-swap-oob=\"delete\"></div>");
        });
        streams.broadcast("sign", render(p));
        return p.result();
    }

    /** @param signature the raw signature made on the phone (Ed25519, or RSASSA-PKCS1-v1_5) */
    public void approve(String id, byte[] signature) {
        Pending p = find(id);
        byte[] blob = SshWire.signatureBlob(p.algorithm(), signature);
        if (!SshWire.verify(p.key().publicKey(), p.data(), blob)) {
            throw new IllegalArgumentException("the signature does not match the key");
        }
        p.result().complete(blob);
    }

    public void deny(String id) {
        find(id).result().completeExceptionally(new DeniedException());
    }

    public List<Pending> pending() {
        return pending.values().stream().sorted(Comparator.comparing(Pending::requestedAt)).toList();
    }

    private Pending find(String id) {
        Pending p = pending.get(id);
        if (p == null) {
            throw new NoSuchElementException("no such request (answered or expired)");
        }
        return p;
    }

    private String render(Pending p) {
        Context ctx = new Context();
        ctx.setVariable("p", p);
        // Newlines would split the SSE data field into several lines.
        return templates.process("fragments/sign", Set.of("sign"), ctx).replace('\n', ' ');
    }
}
