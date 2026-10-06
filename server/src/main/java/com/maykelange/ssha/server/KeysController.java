package com.maykelange.ssha.server;

import java.security.Principal;
import java.util.Base64;
import java.util.Map;
import java.util.NoSuchElementException;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.server.ResponseStatusException;

/**
 * The phone's side of the SSH agent: managing its keys and answering sign requests. Keys are
 * generated and used in the browser (ssh.js); the server only ever sees public keys and signatures.
 */
@Controller
public class KeysController {

    private final SshKeys sshKeys;
    private final SignService signs;

    public KeysController(SshKeys sshKeys, SignService signs) {
        this.sshKeys = sshKeys;
        this.signs = signs;
    }

    @GetMapping("/keys")
    public String keys(Principal principal, Model model) {
        model.addAttribute("keys", sshKeys.findAll(principal.getName()));
        return "keys";
    }

    /** @param publicKey the SSH public key blob (Ed25519 or RSA), base64url */
    public record NewKey(String label, String publicKey) {
    }

    @PostMapping(value = "/keys", consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public Map<String, String> add(@RequestBody NewKey request, Principal principal) {
        String label = request.label() == null ? "" : request.label().strip();
        if (label.isEmpty() || label.length() > 100 || label.chars().anyMatch(Character::isISOControl)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid label");
        }
        byte[] blob;
        try {
            blob = Base64.getUrlDecoder().decode(request.publicKey());
            SshWire.checkUserKey(blob);
        } catch (NullPointerException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid public key");
        }
        // The same key imported on another device is the same key: keep the existing entry.
        SshKey key = sshKeys.findByPublicKey(principal.getName(), blob)
                .orElseGet(() -> sshKeys.add(principal.getName(), label, blob));
        return Map.of("id", key.id(), "authorizedKey", key.authorizedKey());
    }

    @PostMapping("/keys/{id}/delete")
    public String delete(@PathVariable String id, Principal principal) {
        if (!sshKeys.delete(principal.getName(), id)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        return "redirect:/keys";
    }

    /** Tells the phone why a key was refused (e.g. an RSA key that is too short). */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<String> badKey(IllegalArgumentException e) {
        return ResponseEntity.badRequest().contentType(MediaType.TEXT_PLAIN).body(e.getMessage());
    }

    /** @param signature the raw signature, base64url */
    @PostMapping("/sign/{id}/approve")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void approve(@PathVariable String id, @RequestParam String signature, Principal principal) {
        try {
            signs.approve(principal.getName(), id, Base64.getUrlDecoder().decode(signature));
        } catch (NoSuchElementException e) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, e.getMessage());
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }

    @PostMapping("/sign/{id}/deny")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deny(@PathVariable String id, Principal principal) {
        try {
            signs.deny(principal.getName(), id);
        } catch (NoSuchElementException e) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, e.getMessage());
        }
    }
}
