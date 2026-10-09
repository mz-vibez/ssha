package com.maykelange.ssha.server;

import java.io.IOException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpSessionEvent;
import jakarta.servlet.http.HttpSessionIdListener;
import jakarta.servlet.http.HttpSessionListener;

/**
 * The browsers (phones, home-screen apps, desktops) currently signed in to each account, so the phone
 * can list them and sign one out. Sessions live in memory, so this does too.
 */
@Component
public class BrowserSessions extends OncePerRequestFilter implements HttpSessionListener, HttpSessionIdListener {

    /**
     * @param handle  an opaque id for the page's sign-out button; never the session id, which is the cookie
     * @param label   address and user agent, as when the browser first came in
     * @param current whether it is the browser asking
     */
    public record Browser(String handle, String label, Instant since, Instant lastSeen, boolean current) {
    }

    private static final class Entry {
        final String handle = Long.toHexString(RANDOM.nextLong()) + Long.toHexString(RANDOM.nextLong());
        final HttpSession session;
        final String account;
        final String label;
        final Instant since = Instant.now();
        volatile Instant lastSeen = since;

        Entry(HttpSession session, String account, String label) {
            this.session = session;
            this.account = account;
            this.label = label;
        }
    }

    private static final SecureRandom RANDOM = new SecureRandom();

    private final Map<String, Entry> sessions = new ConcurrentHashMap<>();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        // Before the chain so a page lists the browser asking; after it for the request that signs in.
        seen(request);
        chain.doFilter(request, response);
        seen(request);
    }

    private void seen(HttpServletRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        HttpSession session = request.getSession(false);
        if (session != null && auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken)) {
            try {
                Entry entry = sessions.computeIfAbsent(session.getId(),
                        id -> new Entry(session, auth.getName(), ActivityLog.describe(request)));
                entry.lastSeen = Instant.now();
            } catch (IllegalStateException invalidated) {
                // signed out during this very request
            }
        }
    }

    /** The account's signed-in browsers, newest first; {@code currentSessionId} marks the asking one. */
    public List<Browser> of(String account, String currentSessionId) {
        return sessions.entrySet().stream()
                .filter(e -> e.getValue().account.equals(account))
                .map(e -> new Browser(e.getValue().handle, e.getValue().label, e.getValue().since, e.getValue().lastSeen,
                        e.getKey().equals(currentSessionId)))
                .sorted(Comparator.comparing(Browser::since).reversed())
                .toList();
    }

    /** Signs a browser out of the account; the label of the browser, or null if it is not one of its. */
    public String revoke(String account, String handle) {
        var found = sessions.entrySet().stream()
                .filter(e -> e.getValue().handle.equals(handle) && e.getValue().account.equals(account))
                .findFirst();
        if (found.isEmpty()) {
            return null;
        }
        Entry entry = found.get().getValue();
        sessions.remove(found.get().getKey());
        try {
            entry.session.invalidate();
        } catch (IllegalStateException alreadyGone) {
            // expired in the meantime
        }
        return entry.label;
    }

    @Override
    public void sessionDestroyed(HttpSessionEvent event) {
        sessions.remove(event.getSession().getId());
    }

    @Override
    public void sessionIdChanged(HttpSessionEvent event, String oldSessionId) {
        Entry entry = sessions.remove(oldSessionId);
        if (entry != null) {
            sessions.put(event.getSession().getId(), entry);
        }
    }
}
