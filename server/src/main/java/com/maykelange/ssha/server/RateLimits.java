package com.maykelange.ssha.server;

import java.time.Duration;
import java.util.List;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * The limits on what callers can make the server do, so that neither strangers nor a stolen computer
 * token can flood the database or the phone. Each request to the phone is a push notification, and a
 * steady stream of them is how someone gets tired enough to tap Approve.
 */
@Component
public class RateLimits {

    /** New accounts per IP address, from the CLI and the phone together. */
    final RateLimiter accountsPerAddress = new RateLimiter(10, Duration.ofHours(1));
    /** Join requests per IP address, whatever the account. */
    final RateLimiter joinsPerAddress = new RateLimiter(20, Duration.ofMinutes(10));
    /** Join requests per account, whoever asks: each one notifies the phone. */
    final RateLimiter joinsPerAccount = new RateLimiter(10, Duration.ofMinutes(10));
    /** Requests for a sign-in link per account, each one notifies the phone. */
    final RateLimiter enrollsPerAccount = new RateLimiter(5, Duration.ofMinutes(10));
    /**
     * Sign requests per computer. Generous for real use (a git push or an Ansible run asks a few
     * times), but a computer can't keep the phone buzzing.
     */
    final RateLimiter signsPerClient = new RateLimiter(20, Duration.ofMinutes(1));

    private List<RateLimiter> all() {
        return List.of(accountsPerAddress, joinsPerAddress, joinsPerAccount, enrollsPerAccount, signsPerClient);
    }

    @Scheduled(fixedRate = 600_000)
    public void cleanUp() {
        all().forEach(RateLimiter::cleanUp);
    }

    /** Forgets every count (tests). */
    void clear() {
        all().forEach(RateLimiter::clear);
    }
}
