package com.maykelange.ssha.server;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import org.junit.jupiter.api.Test;

class RateLimiterTest {

    /** A clock the test moves by hand. */
    static final class ManualClock extends Clock {
        Instant now = Instant.parse("2026-10-07T12:00:00Z");

        @Override
        public Instant instant() {
            return now;
        }

        @Override
        public java.time.ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }
    }

    @Test
    void allowsUpToTheLimitPerKeyWithinTheWindow() {
        ManualClock clock = new ManualClock();
        RateLimiter limiter = new RateLimiter(2, Duration.ofMinutes(1), clock);
        assertThat(limiter.tryAcquire("a")).isTrue();
        clock.now = clock.now.plusSeconds(30);
        assertThat(limiter.tryAcquire("a")).isTrue();
        assertThat(limiter.tryAcquire("a")).isFalse();
        assertThat(limiter.tryAcquire("b")).isTrue();

        // The window slides: the first event expires, the second still counts.
        clock.now = clock.now.plusSeconds(31);
        assertThat(limiter.tryAcquire("a")).isTrue();
        assertThat(limiter.tryAcquire("a")).isFalse();
    }

    @Test
    void refusedAttemptsDontExtendTheWait() {
        ManualClock clock = new ManualClock();
        RateLimiter limiter = new RateLimiter(1, Duration.ofMinutes(1), clock);
        assertThat(limiter.tryAcquire("a")).isTrue();
        for (int i = 0; i < 50; i++) {
            clock.now = clock.now.plusSeconds(1);
            limiter.tryAcquire("a");
        }
        clock.now = clock.now.plusSeconds(10);
        assertThat(limiter.tryAcquire("a")).isTrue();
    }
}
