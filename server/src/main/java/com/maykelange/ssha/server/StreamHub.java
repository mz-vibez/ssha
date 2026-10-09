package com.maykelange.ssha.server;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.BiConsumer;

import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

/**
 * Server-Sent Event connections of open phone pages, by account; they receive server-rendered HTML
 * fragments.
 */
@Component
public class StreamHub {

    private static final long TIMEOUT_MS = 30 * 60 * 1000L;

    private final Map<String, List<SseEmitter>> emitters = new ConcurrentHashMap<>();
    private final List<BiConsumer<String, SseEmitter>> connectListeners = new CopyOnWriteArrayList<>();

    public SseEmitter open(String accountId) {
        SseEmitter emitter = new SseEmitter(TIMEOUT_MS);
        Runnable cleanup = () -> emitters.computeIfPresent(accountId, (id, list) -> {
            list.remove(emitter);
            return list.isEmpty() ? null : list;
        });
        emitter.onCompletion(cleanup);
        emitter.onTimeout(cleanup);
        emitter.onError(e -> cleanup.run());

        emitters.computeIfAbsent(accountId, id -> new CopyOnWriteArrayList<>()).add(emitter);
        try {
            synchronized (emitter) {
                emitter.send(SseEmitter.event().comment("connected"));
            }
        } catch (IOException e) {
            cleanup.run();
            return emitter;
        }
        connectListeners.forEach(l -> l.accept(accountId, emitter));
        // Everything pending has been sent: the page can drop cards it showed from a push that are gone.
        send(emitter, "synced", "");
        return emitter;
    }

    /** Called with every new page connection and its account, e.g. to send it what is currently pending. */
    public void onConnect(BiConsumer<String, SseEmitter> listener) {
        connectListeners.add(listener);
    }

    /** Sends a named event to the account's open pages. */
    public void broadcast(String accountId, String name, String html) {
        emitters.getOrDefault(accountId, List.of()).forEach(e -> send(e, name, html));
    }

    public void send(SseEmitter emitter, String name, String html) {
        try {
            synchronized (emitter) {
                emitter.send(SseEmitter.event().name(name).data(html, MediaType.TEXT_HTML));
            }
        } catch (IOException | IllegalStateException e) {
            emitter.completeWithError(e);
        }
    }

    /**
     * Keeps idle connections alive through the load balancer. A real event, not a comment: the page
     * can only see events, and treats a stream that went quiet for too long as dead.
     */
    @Scheduled(fixedRate = 20_000)
    public void heartbeat() {
        for (List<SseEmitter> list : emitters.values()) {
            for (SseEmitter emitter : list) {
                try {
                    synchronized (emitter) {
                        emitter.send(SseEmitter.event().name("ping").data(""));
                    }
                } catch (IOException | IllegalStateException e) {
                    emitter.completeWithError(e);
                }
            }
        }
    }
}
