package com.maykelange.ssha.server;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeoutException;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.async.DeferredResult;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

/** JSON API used by the CLI. Every endpoint requires the bearer token (see {@link SecurityConfig}). */
@RestController
@RequestMapping("/api")
public class ApiController {

    private static final Duration ENROLL_LINK_VALIDITY = Duration.ofMinutes(10);

    private final OneTimeTokenService oneTimeTokens;
    private final SshaProperties props;
    private final SshKeys sshKeys;
    private final SignService signs;

    public ApiController(OneTimeTokenService oneTimeTokens, SshaProperties props, SshKeys sshKeys,
                         SignService signs) {
        this.oneTimeTokens = oneTimeTokens;
        this.props = props;
        this.sshKeys = sshKeys;
        this.signs = signs;
    }

    public record EnrollLink(String url, Instant expiresAt) {
    }

    /** A single-use sign-in link for the phone, used to register a (first or additional) passkey. */
    @PostMapping("/enroll")
    public EnrollLink enroll() {
        OneTimeToken token = oneTimeTokens.generate(
                new GenerateOneTimeTokenRequest(props.username(), ENROLL_LINK_VALIDITY));
        String url = ServletUriComponentsBuilder.fromCurrentContextPath()
                .path("/login/ott")
                .queryParam("token", token.getTokenValue())
                .toUriString();
        return new EnrollLink(url, token.getExpiresAt());
    }

    public record AgentKey(String id, String label, byte[] publicKey, String authorizedKey) {
    }

    /** The keys the agent offers to ssh. */
    @GetMapping("/keys")
    public List<AgentKey> keys() {
        return sshKeys.findAll().stream()
                .map(k -> new AgentKey(k.id(), k.label(), k.publicKey(), k.authorizedKey()))
                .toList();
    }

    /**
     * @param publicKey SSH public key blob of the key to sign with
     * @param data      the bytes ssh wants signed
     * @param binding   the agent connection's last session binding, if ssh sent one
     * @param client    shown on the phone, e.g. the host name the agent runs on
     */
    public record SignRequest(byte[] publicKey, byte[] data, int flags, String client, SignService.Binding binding) {
    }

    public record SignResponse(byte[] signature) {
    }

    /**
     * Waits until the request is approved (200 with an SSH signature blob), denied (403) or not
     * answered in time (408) on the phone.
     */
    @PostMapping("/sign")
    public DeferredResult<ResponseEntity<?>> sign(@RequestBody SignRequest request) {
        if (request.publicKey() == null || request.data() == null) {
            throw new IllegalArgumentException("publicKey and data are required");
        }
        if (request.data().length > SignService.MAX_DATA_LENGTH) {
            throw new IllegalArgumentException("data too long");
        }
        SshKey key = sshKeys.findByPublicKey(request.publicKey())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "unknown key"));
        String client = request.client() == null || request.client().isBlank() ? "cli" : request.client().strip();
        CompletableFuture<byte[]> result = signs.request(key, request.data(), request.flags(), request.binding(),
                client.length() > 100 ? client.substring(0, 100) : client);

        DeferredResult<ResponseEntity<?>> response = new DeferredResult<>();
        // The agent gave up (ssh was interrupted): take the request off the phone.
        response.onError(e -> result.cancel(false));
        result.whenComplete((signature, error) -> response.setResult(switch (error) {
            case null -> ResponseEntity.ok(new SignResponse(signature));
            case SignService.DeniedException e -> ResponseEntity.status(HttpStatus.FORBIDDEN).body(e.getMessage());
            case TimeoutException e -> ResponseEntity.status(HttpStatus.REQUEST_TIMEOUT).body("not answered on the phone in time");
            case CancellationException e -> ResponseEntity.status(HttpStatus.GONE).build();
            default -> ResponseEntity.internalServerError().build();
        }));
        return response;
    }

    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public String badRequest(IllegalArgumentException e) {
        return e.getMessage();
    }
}
