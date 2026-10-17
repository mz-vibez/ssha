package com.maykelange.ssha.server.vault;

import java.security.Principal;
import java.util.Base64;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeoutException;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;

import com.maykelange.ssha.server.activity.ActivityLog;
import com.maykelange.ssha.server.security.Passkeys;
import com.maykelange.ssha.server.ssh.SignService;
import com.maykelange.ssha.server.ssh.SshKeys;

/**
 * The browser's view of the vault (ssh.js): the encrypted vault key per passkey, the encrypted SSH
 * keys, and devices asking for the vault key. Binary values are base64url.
 */
@RestController
@RequestMapping("/vault")
public class VaultController {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    private final VaultSlots slots;
    private final VaultJoins joins;
    private final SshKeys sshKeys;
    private final Passkeys passkeys;
    private final ActivityLog activity;

    public VaultController(VaultSlots slots, VaultJoins joins, SshKeys sshKeys, Passkeys passkeys, ActivityLog activity) {
        this.slots = slots;
        this.joins = joins;
        this.sshKeys = sshKeys;
        this.passkeys = passkeys;
        this.activity = activity;
    }

    public record Slot(String credentialId, String iv, String wrapped) {
    }

    public record Key(String id, String type, String publicKey, String iv, String data) {
    }

    /** @param salt the PRF input to ask every passkey of the account for */
    public record Vault(String salt, List<Slot> slots, List<Key> keys) {
    }

    @GetMapping
    public Vault vault(Principal principal) {
        String account = principal.getName();
        return new Vault(B64URL.encodeToString(VaultSlots.salt(account)),
                slots.findAll(account).stream()
                        .map(s -> new Slot(s.credentialId(), B64URL.encodeToString(s.iv()), B64URL.encodeToString(s.wrapped())))
                        .toList(),
                sshKeys.sealed(account).stream()
                        .map(k -> new Key(k.id(), k.type(), B64URL.encodeToString(k.publicKey()),
                                B64URL.encodeToString(k.iv()), B64URL.encodeToString(k.data())))
                        .toList());
    }

    /** @param create true to bring the account's vault key into being (only while it has none) */
    public record NewSlot(String credentialId, String iv, String wrapped, boolean create) {
    }

    @PostMapping("/slots")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void addSlot(@RequestBody NewSlot request, Principal principal, HttpServletRequest http) {
        String account = principal.getName();
        Bytes credentialId = credential(account, request.credentialId());
        byte[] iv = decode(request.iv());
        byte[] wrapped = decode(request.wrapped());
        if (iv.length != 12 || wrapped.length != 32 + 16) {
            throw new IllegalArgumentException("invalid slot");
        }
        slots.add(account, credentialId, iv, wrapped, request.create());
        joins.joined(account, credentialId);
        activity.web(account, request.create() ? "created the SSH key vault" : "unlocked the SSH keys", null, http);
    }

    public record DeviceRequest(String credentialId, String publicKey) {
    }

    public record DeviceRequested(String id, String code) {
    }

    /** Asks the account's other devices for the vault key; poll {@code GET /vault/devices/{id}} for the answer. */
    @PostMapping("/devices")
    public DeviceRequested requestKey(@RequestBody DeviceRequest request, Principal principal, HttpServletRequest http) {
        String account = principal.getName();
        VaultJoins.Pending p = joins.request(account, credential(account, request.credentialId()),
                decode(request.publicKey()), ActivityLog.describe(http));
        return new DeviceRequested(p.id(), p.code());
    }

    public record Grant(String ephemeralKey, String iv, String data) {
    }

    /** 202 while unanswered, 200 with the grant, 403 denied, 408 not answered in time, 404 gone. */
    @GetMapping("/devices/{id}")
    public ResponseEntity<?> answer(@PathVariable String id, Principal principal) {
        CompletableFuture<VaultJoins.Grant> result = joins.find(principal.getName(), id).result();
        if (!result.isDone()) {
            return ResponseEntity.accepted().build();
        }
        try {
            VaultJoins.Grant g = result.join();
            return ResponseEntity.ok(new Grant(B64URL.encodeToString(g.ephemeralKey()), B64URL.encodeToString(g.iv()),
                    B64URL.encodeToString(g.data())));
        } catch (CompletionException | CancellationException e) {
            Throwable cause = e instanceof CompletionException ? e.getCause() : e;
            return switch (cause) {
                case SignService.DeniedException d -> ResponseEntity.status(HttpStatus.FORBIDDEN).build();
                case TimeoutException t -> ResponseEntity.status(HttpStatus.REQUEST_TIMEOUT).build();
                default -> ResponseEntity.status(HttpStatus.GONE).build();
            };
        }
    }

    @PostMapping("/devices/{id}/approve")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void approve(@PathVariable String id, @RequestBody Grant grant, Principal principal, HttpServletRequest http) {
        joins.approve(principal.getName(), id,
                new VaultJoins.Grant(decode(grant.ephemeralKey()), decode(grant.iv()), decode(grant.data())));
        activity.web(principal.getName(), "gave the SSH keys to a device", null, http);
    }

    @PostMapping("/devices/{id}/deny")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deny(@PathVariable String id, Principal principal) {
        joins.deny(principal.getName(), id);
    }

    private Bytes credential(String account, String credentialId) {
        if (credentialId == null) {
            throw new IllegalArgumentException("missing credential id");
        }
        Bytes id = Bytes.fromBase64(credentialId);
        if (!passkeys.owns(account, id)) {
            throw new NoSuchElementException("not a passkey of this account");
        }
        return id;
    }

    private static byte[] decode(String base64url) {
        if (base64url == null) {
            throw new IllegalArgumentException("missing value");
        }
        return Base64.getUrlDecoder().decode(base64url);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<String> badRequest(IllegalArgumentException e) {
        return ResponseEntity.badRequest().contentType(MediaType.TEXT_PLAIN).body(e.getMessage());
    }

    @ExceptionHandler(NoSuchElementException.class)
    public ResponseEntity<String> notFound(NoSuchElementException e) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).contentType(MediaType.TEXT_PLAIN).body(e.getMessage());
    }

    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<String> conflict(IllegalStateException e) {
        return ResponseEntity.status(HttpStatus.CONFLICT).contentType(MediaType.TEXT_PLAIN).body(e.getMessage());
    }
}
