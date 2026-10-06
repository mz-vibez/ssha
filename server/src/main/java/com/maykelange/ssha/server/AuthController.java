package com.maykelange.ssha.server;

import java.security.Principal;
import java.util.Comparator;
import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.CredentialRecord;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/** Login page, account creation, one-time-link landing page and passkey management. */
@Controller
public class AuthController {

    private final PublicKeyCredentialUserEntityRepository userEntities;
    private final UserCredentialRepository credentials;
    private final Accounts accounts;
    private final UserDetailsService users;
    private final SshaProperties props;
    private final RateLimits limits;
    private final SecurityContextHolderStrategy contexts = SecurityContextHolder.getContextHolderStrategy();
    private final SecurityContextRepository contextRepository = new HttpSessionSecurityContextRepository();

    public AuthController(PublicKeyCredentialUserEntityRepository userEntities, UserCredentialRepository credentials,
                          Accounts accounts, UserDetailsService users, SshaProperties props, RateLimits limits) {
        this.userEntities = userEntities;
        this.credentials = credentials;
        this.accounts = accounts;
        this.users = users;
        this.props = props;
        this.limits = limits;
    }

    @GetMapping("/login")
    public String login(Authentication authentication, Model model) {
        boolean signedIn = authentication != null && !(authentication instanceof AnonymousAuthenticationToken);
        model.addAttribute("openRegistration", props.openRegistration());
        return signedIn ? "redirect:/" : "login";
    }

    /**
     * Creates an account from the phone and signs this browser in to it, then sends it to add the
     * account's first passkey. Computers join it later with {@code ssha-cli --account <id>}.
     */
    @PostMapping("/signup")
    public String signup(HttpServletRequest request, HttpServletResponse response) {
        if (!props.openRegistration()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "this server doesn't accept new accounts");
        }
        if (!limits.accountsPerAddress.tryAcquire(request.getRemoteAddr())) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "too many new accounts from this address");
        }
        UserDetails user = users.loadUserByUsername(accounts.create());
        SecurityContext context = contexts.createEmptyContext();
        context.setAuthentication(UsernamePasswordAuthenticationToken.authenticated(user, null, user.getAuthorities()));
        contexts.setContext(context);
        // A new session id, as after any sign-in, so a planted session can't ride along.
        if (request.getSession(false) != null) {
            request.changeSessionId();
        }
        contextRepository.saveContext(context, request, response);
        return "redirect:/passkeys?new";
    }

    /**
     * Where the link from {@code ssha-cli enroll} lands. It deliberately needs a button press (a POST)
     * so link previews and prefetchers can't burn the token.
     */
    @GetMapping("/login/ott")
    public String oneTimeLogin(@RequestParam(value = "token", required = false) String token, Model model) {
        model.addAttribute("token", token);
        return "ott";
    }

    @GetMapping("/passkeys")
    public String passkeys(Principal principal, Model model) {
        model.addAttribute("passkeys", passkeysOf(principal));
        return "passkeys";
    }

    @PostMapping("/passkeys/{id}/delete")
    public String delete(@PathVariable String id, Principal principal) {
        Bytes credentialId = Bytes.fromBase64(id);
        boolean owned = passkeysOf(principal).stream().anyMatch(c -> c.getCredentialId().equals(credentialId));
        if (!owned) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        credentials.delete(credentialId);
        return "redirect:/passkeys";
    }

    private List<CredentialRecord> passkeysOf(Principal principal) {
        PublicKeyCredentialUserEntity user = userEntities.findByUsername(principal.getName());
        if (user == null) {
            return List.of();
        }
        return credentials.findByUserId(user.getId()).stream()
                .sorted(Comparator.comparing(CredentialRecord::getCreated))
                .toList();
    }
}
