package com.maykelange.ssha.server;

import java.security.Principal;
import java.util.Comparator;
import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
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

/** Login page, one-time-link landing page and passkey management. */
@Controller
public class AuthController {

    private final PublicKeyCredentialUserEntityRepository userEntities;
    private final UserCredentialRepository credentials;

    public AuthController(PublicKeyCredentialUserEntityRepository userEntities, UserCredentialRepository credentials) {
        this.userEntities = userEntities;
        this.credentials = credentials;
    }

    @GetMapping("/login")
    public String login(Authentication authentication) {
        boolean signedIn = authentication != null && !(authentication instanceof AnonymousAuthenticationToken);
        return signedIn ? "redirect:/" : "login";
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
