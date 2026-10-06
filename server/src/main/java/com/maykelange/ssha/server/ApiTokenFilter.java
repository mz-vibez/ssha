package com.maykelange.ssha.server;

import java.io.IOException;
import java.util.List;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Authenticates {@code Authorization: Bearer <token>} requests from the CLI. The principal's name is
 * the account id, like a signed-in phone's, so both sides see the same account.
 */
class ApiTokenFilter extends OncePerRequestFilter {

    private static final String PREFIX = "Bearer ";

    private final Accounts accounts;
    private final SecurityContextHolderStrategy contexts = SecurityContextHolder.getContextHolderStrategy();

    ApiTokenFilter(Accounts accounts) {
        this.accounts = accounts;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith(PREFIX)) {
            accounts.authenticate(header.substring(PREFIX.length()).strip()).ifPresent(client -> {
                SecurityContext context = contexts.createEmptyContext();
                context.setAuthentication(UsernamePasswordAuthenticationToken.authenticated(
                        client.accountId(), null, List.of(new SimpleGrantedAuthority("ROLE_CLI"))));
                contexts.setContext(context);
            });
        }
        chain.doFilter(request, response);
    }
}
