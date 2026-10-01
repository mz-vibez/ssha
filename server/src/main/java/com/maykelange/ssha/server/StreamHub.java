package com.maykelange.ssha.server;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

/** Server-Sent Event connections of open phone pages; they receive server-rendered HTML fragments. */
@Component
public class StreamHub {

    private static final long TIMEOUT_MS = 30 * 60 * 1000L;

    private final List<SseEmitter> emitters = new CopyOnWriteArrayList<>();
    private final List<Consumer<SseEmitter>> connectListeners = new CopyOnWriteArrayList<>();

    public SseEmitter open() {
        SseEmitter emitter = new SseEmitter(TIMEOUT_MS);
        Runnable cleanup = () -> emitters.remove(emitter);
        emitter.onCompletion(cleanup);
        emitter.onTimeout(cleanup);
        emitter.onError(e -> cleanup.run());

        emitters.add(emitter);
        try {
            synchronized (emitter) {
                emitter.send(SseEmitter.event().comment("connected"));
            }
        } catch (IOException e) {
            cleanup.run();
            return emitter;
        }
        connectListeners.forEach(l -> l.accept(emitter));
        return emitter;
    }

    /** Called with every new page connection, e.g. to send it what is currently pending. */
    public void onConnect(Consumer<SseEmitter> listener) {
        connectListeners.add(listener);
    }

    /** Sends a named event to all open pages. */
    public void broadcast(String name, String html) {
        emitters.forEach(e -> send(e, name, html));
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

    /** Keeps idle connections alive through the load balancer. */
    @Scheduled(fixedRate = 20_000)
    public void heartbeat() {
        for (SseEmitter emitter : emitters) {
            try {
                synchronized (emitter) {
                    emitter.send(SseEmitter.event().comment("ping"));
                }
            } catch (IOException | IllegalStateException e) {
                emitter.completeWithError(e);
            }
        }
    }
}
