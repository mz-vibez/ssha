package com.maykelange.ssha.server;

import java.util.UUID;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.ott.InMemoryOneTimeTokenService;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.webauthn.management.JdbcPublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.JdbcUserCredentialRepository;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Two filter chains:
 * <ul>
 * <li>{@code /api/**} — the CLI, stateless, a bearer token per computer. Creating an account and
 * asking to join one are the only anonymous calls.</li>
 * <li>everything else — the phone, session based. Sign-in is by passkey; a one-time link from
 * {@code ssha-cli enroll} is the bootstrap for registering the first passkey (and recovery).</li>
 * </ul>
 */
@Configuration
public class SecurityConfig {

    /**
     * Only this server's own scripts, styles and connections: the start page decrypts SSH keys, so no
     * inline script, eval or third-party code may run there.
     */
    static final String CONTENT_SECURITY_POLICY = "default-src 'self'; script-src 'self'; style-src 'self'; "
            + "img-src 'self'; connect-src 'self'; manifest-src 'self'; worker-src 'self'; object-src 'none'; "
            + "base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

    @Bean
    @Order(1)
    SecurityFilterChain apiChain(HttpSecurity http, Accounts accounts) throws Exception {
        http.securityMatcher("/api/**")
                .authorizeHttpRequests(a -> a
                        // SSE responses complete on async dispatches; the request was authorised already.
                        .dispatcherTypeMatchers(DispatcherType.ASYNC, DispatcherType.ERROR).permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/accounts", "/api/accounts/*/clients").permitAll()
                        .anyRequest().hasRole("CLI"))
                .addFilterBefore(new ApiTokenFilter(accounts), AuthorizationFilter.class)
                .csrf(c -> c.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .requestCache(c -> c.disable())
                .exceptionHandling(e -> e.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)));
        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain webChain(HttpSecurity http, SshaProperties props, OneTimeTokenService oneTimeTokens)
            throws Exception {
        http.authorizeHttpRequests(a -> a
                        .dispatcherTypeMatchers(DispatcherType.ASYNC, DispatcherType.ERROR).permitAll()
                        .requestMatchers("/login", "/login/ott", "/app.css", "/webauthn.js", "/favicon.ico", "/error")
                        .permitAll()
                        // The PWA's files: the browser fetches them without (or after the end of) a session.
                        .requestMatchers("/manifest.webmanifest", "/sw.js", "/push.js", "/confirm.js", "/icon-*.png")
                        .permitAll()
                        .requestMatchers("/webjars/**").permitAll()
                        // The CLI: fetched with curl on computers that have no session.
                        .requestMatchers("/download/*").permitAll()
                        .requestMatchers(HttpMethod.POST, "/signup").permitAll()
                        .anyRequest().authenticated())
                .webAuthn(w -> w
                        .rpName("ssha")
                        .rpId(props.rpId())
                        .allowedOrigins(props.allowedOrigins())
                        .disableDefaultRegistrationPage(true))
                .oneTimeTokenLogin(ott -> ott
                        .loginPage("/login")
                        // loginPage() would otherwise move the processing URL to POST /login as well.
                        .loginProcessingUrl("/login/ott")
                        .tokenService(oneTimeTokens)
                        // Links are only handed out through the authenticated /api/enroll endpoint, so the
                        // public "generate a token" endpoint never delivers anything.
                        .tokenGenerationSuccessHandler((req, res, token) -> res.sendError(HttpStatus.NOT_FOUND.value()))
                        .showDefaultSubmitPage(false)
                        .successHandler(new SimpleUrlAuthenticationSuccessHandler("/passkeys")))
                .logout(l -> l.logoutSuccessUrl("/login?logout"))
                .headers(h -> h.contentSecurityPolicy(c -> c.policyDirectives(CONTENT_SECURITY_POLICY)))
                .exceptionHandling(e -> e.authenticationEntryPoint(entryPoint()));
        return http.build();
    }

    /**
     * Full page loads go to the login page. htmx requests and the event stream can't follow a redirect
     * to an HTML page usefully, so they get a 401 and the page's script sends the user to /login.
     */
    private static AuthenticationEntryPoint entryPoint() {
        AuthenticationEntryPoint login = new LoginUrlAuthenticationEntryPoint("/login");
        AuthenticationEntryPoint unauthorized = new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED);
        return (request, response, ex) -> (isBackgroundRequest(request) ? unauthorized : login)
                .commence(request, response, ex);
    }

    private static boolean isBackgroundRequest(HttpServletRequest request) {
        return request.getHeader("HX-Request") != null
                || request.getRequestURI().equals(request.getContextPath() + "/stream");
    }

    /**
     * One user per account, named by the account id. None has a usable password: passkeys and
     * one-time links are the only ways in.
     */
    @Bean
    UserDetailsService users(Accounts accounts) {
        return username -> {
            if (!accounts.exists(username)) {
                throw new UsernameNotFoundException("no such account");
            }
            return User.withUsername(username).password("{noop}" + UUID.randomUUID()).roles("USER").build();
        };
    }

    @Bean
    OneTimeTokenService oneTimeTokenService() {
        return new InMemoryOneTimeTokenService();
    }

    @Bean
    PublicKeyCredentialUserEntityRepository userEntities(DataSource dataSource) {
        return new JdbcPublicKeyCredentialUserEntityRepository(new JdbcTemplate(dataSource));
    }

    @Bean
    UserCredentialRepository userCredentials(DataSource dataSource) {
        return new JdbcUserCredentialRepository(new JdbcTemplate(dataSource));
    }
}
