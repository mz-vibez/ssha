package com.maykelange.ssha.server;

import java.time.Instant;
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
 * Computers asking for a sign-in link ({@code ssha-cli enroll}) for an account that already has a
 * passkey. The link signs a browser in to the whole account, so a computer's token alone mustn't be
 * enough: the phone has to accept. (An account without a passkey has no phone to ask; its first
 * link is handed out directly.)
 */
@Service
public class EnrollService {

    /** Most requests one account may have waiting. */
    static final int MAX_PENDING_PER_ACCOUNT = 1;

    /**
     * @param client the computer asking, as stored when it joined
     * @param code   shown both in the terminal and on the phone
     */
    public record Pending(String id, Accounts.Client client, String code, Instant requestedAt,
                          CompletableFuture<Void> result) {
    }

    private final Map<String, Pending> pending = new ConcurrentHashMap<>();
    private final StreamHub streams;
    private final TemplateEngine templates;
    private final SshaProperties props;
    private final PushService push;

    public EnrollService(StreamHub streams, TemplateEngine templates, SshaProperties props, PushService push) {
        this.streams = streams;
        this.templates = templates;
        this.props = props;
        this.push = push;
        streams.onConnect((account, emitter) -> pending(account).forEach(p -> streams.send(emitter, "sign", render(p))));
    }

    /**
     * Shows the request on the account's phone. The future completes when it is accepted, or fails
     * with {@link SignService.DeniedException}, a {@link java.util.concurrent.TimeoutException}, or a
     * cancellation.
     *
     * @throws IllegalStateException if the account has a request waiting already
     */
    public synchronized CompletableFuture<Void> request(Accounts.Client client, String code) {
        String accountId = client.accountId();
        if (pending(accountId).size() >= MAX_PENDING_PER_ACCOUNT) {
            throw new IllegalStateException("a sign-in link request is already waiting for this account");
        }
        Pending p = new Pending(Accounts.randomId(16), client, code, Instant.now(), new CompletableFuture<>());
        pending.put(p.id(), p);
        p.result().orTimeout(props.joinTimeout().toMillis(), TimeUnit.MILLISECONDS).whenComplete((ok, error) -> {
            pending.remove(p.id());
            streams.broadcast(accountId, "sign", "<div id=\"enroll-" + p.id() + "\" hx-swap-oob=\"delete\"></div>");
        });
        streams.broadcast(accountId, "sign", render(p));
        push.notify(accountId, new PushService.Notification("Sign-in link",
                client.name() + " asks for a link to add a passkey to this account"
                        + (code.isEmpty() ? "" : ", code " + code),
                "enroll-" + p.id(), props.joinTimeout()));
        return p.result();
    }

    public void accept(String accountId, String id) {
        find(accountId, id).result().complete(null);
    }

    public void deny(String accountId, String id) {
        find(accountId, id).result().completeExceptionally(new SignService.DeniedException());
    }

    public List<Pending> pending(String accountId) {
        return pending.values().stream()
                .filter(p -> p.client().accountId().equals(accountId))
                .sorted(Comparator.comparing(Pending::requestedAt))
                .toList();
    }

    private Pending find(String accountId, String id) {
        Pending p = pending.get(id);
        if (p == null || !p.client().accountId().equals(accountId)) {
            throw new NoSuchElementException("no such request (answered or expired)");
        }
        return p;
    }

    private String render(Pending p) {
        Context ctx = new Context();
        ctx.setVariable("p", p);
        return templates.process("fragments/enroll", Set.of("enroll"), ctx).replace('\n', ' ');
    }
}
