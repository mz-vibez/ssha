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
 * Computers asking to join an account ({@code ssha-cli --account <id>}). The request is shown on the
 * account's phone; accepting it creates a client whose token goes back to the waiting computer.
 */
@Service
public class JoinService {

    /** Most pending requests one account may have, so an id that leaked can't flood the phone. */
    static final int MAX_PENDING_PER_ACCOUNT = 5;

    /**
     * @param code    shown both in the terminal and on the phone, so the user can tell their own
     *                computer's request from someone else's
     * @param address the IP address the request came from
     */
    public record Pending(String id, String accountId, String client, String code, String address,
                          Instant requestedAt, CompletableFuture<Accounts.Enrolled> result) {
    }

    private final Map<String, Pending> pending = new ConcurrentHashMap<>();
    private final Accounts accounts;
    private final StreamHub streams;
    private final TemplateEngine templates;
    private final SshaProperties props;

    public JoinService(Accounts accounts, StreamHub streams, TemplateEngine templates, SshaProperties props) {
        this.accounts = accounts;
        this.streams = streams;
        this.templates = templates;
        this.props = props;
        streams.onConnect((account, emitter) -> pending(account).forEach(p -> streams.send(emitter, "sign", render(p))));
    }

    /**
     * Shows the request on the account's phone. The future completes with the new client, or fails
     * with {@link SignService.DeniedException}, a {@link java.util.concurrent.TimeoutException}, or a
     * cancellation.
     *
     * @throws NoSuchElementException if there is no such account
     * @throws IllegalStateException  if the account has too many requests waiting already
     */
    public synchronized CompletableFuture<Accounts.Enrolled> request(String accountId, String client, String code,
                                                                     String address) {
        if (!accounts.exists(accountId)) {
            throw new NoSuchElementException("no such account");
        }
        if (pending(accountId).size() >= MAX_PENDING_PER_ACCOUNT) {
            throw new IllegalStateException("too many requests waiting for this account");
        }
        Pending p = new Pending(Accounts.randomId(16), accountId, client, code, address, Instant.now(),
                new CompletableFuture<>());
        pending.put(p.id(), p);
        p.result().orTimeout(props.joinTimeout().toMillis(), TimeUnit.MILLISECONDS).whenComplete((enrolled, error) -> {
            pending.remove(p.id());
            streams.broadcast(accountId, "sign", "<div id=\"join-" + p.id() + "\" hx-swap-oob=\"delete\"></div>");
        });
        streams.broadcast(accountId, "sign", render(p));
        return p.result();
    }

    public void accept(String accountId, String id) {
        Pending p = find(accountId, id);
        // Only one answer creates a client, even if the phone sends two.
        if (pending.remove(id) != null) {
            p.result().complete(accounts.addClient(accountId, p.client()));
        }
    }

    public void deny(String accountId, String id) {
        find(accountId, id).result().completeExceptionally(new SignService.DeniedException());
    }

    public List<Pending> pending(String accountId) {
        return pending.values().stream()
                .filter(p -> p.accountId().equals(accountId))
                .sorted(Comparator.comparing(Pending::requestedAt))
                .toList();
    }

    private Pending find(String accountId, String id) {
        Pending p = pending.get(id);
        if (p == null || !p.accountId().equals(accountId)) {
            throw new NoSuchElementException("no such request (answered or expired)");
        }
        return p;
    }

    private String render(Pending p) {
        Context ctx = new Context();
        ctx.setVariable("p", p);
        return templates.process("fragments/join", Set.of("join"), ctx).replace('\n', ' ');
    }
}
