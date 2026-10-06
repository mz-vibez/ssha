package com.maykelange.ssha.server;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * At most {@code limit} events per key (an IP address, an account, a computer) within a sliding
 * {@code window}. In memory, like the pending requests it protects: a restart forgets it.
 */
public class RateLimiter {

    private final int limit;
    private final Duration window;
    private final Clock clock;
    private final Map<String, Deque<Long>> events = new ConcurrentHashMap<>();

    public RateLimiter(int limit, Duration window) {
        this(limit, window, Clock.systemUTC());
    }

    RateLimiter(int limit, Duration window, Clock clock) {
        this.limit = limit;
        this.window = window;
        this.clock = clock;
    }

    /** Records an event for {@code key}; false (and nothing recorded) if the key is over its limit. */
    public boolean tryAcquire(String key) {
        long now = clock.millis();
        boolean[] allowed = new boolean[1];
        events.compute(key, (k, times) -> {
            Deque<Long> t = times == null ? new ArrayDeque<>() : times;
            dropExpired(t, now);
            allowed[0] = t.size() < limit;
            if (allowed[0]) {
                t.addLast(now);
            }
            return t.isEmpty() ? null : t;
        });
        return allowed[0];
    }

    /** Forgets keys whose events have all expired, so the map doesn't grow with every caller ever seen. */
    public void cleanUp() {
        long now = clock.millis();
        events.keySet().forEach(key -> events.computeIfPresent(key, (k, t) -> {
            dropExpired(t, now);
            return t.isEmpty() ? null : t;
        }));
    }

    /** Forgets everything (tests). */
    void clear() {
        events.clear();
    }

    private void dropExpired(Deque<Long> times, long now) {
        long oldest = now - window.toMillis();
        while (!times.isEmpty() && times.peekFirst() <= oldest) {
            times.removeFirst();
        }
    }
}
