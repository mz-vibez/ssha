package com.maykelange.ssha.server;

import java.security.Principal;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.NoSuchElementException;
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
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.async.DeferredResult;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import jakarta.servlet.http.HttpServletRequest;

/**
 * JSON API used by the CLI. Every endpoint requires a client's bearer token (see {@link SecurityConfig}),
 * except creating an account and asking to join one, which is how a computer gets its token.
 */
@RestController
@RequestMapping("/api")
public class ApiController {

    private static final Duration ENROLL_LINK_VALIDITY = Duration.ofMinutes(10);

    private final OneTimeTokenService oneTimeTokens;
    private final SshaProperties props;
    private final Accounts accounts;
    private final JoinService joins;
    private final SshKeys sshKeys;
    private final SignService signs;

    public ApiController(OneTimeTokenService oneTimeTokens, SshaProperties props, Accounts accounts,
                         JoinService joins, SshKeys sshKeys, SignService signs) {
        this.oneTimeTokens = oneTimeTokens;
        this.props = props;
        this.accounts = accounts;
        this.joins = joins;
        this.sshKeys = sshKeys;
        this.signs = signs;
    }

    /** @param client a name for the computer, e.g. its host name */
    public record NewClient(String client) {
    }

    /** @param token the computer's bearer token; it is not stored anywhere in clear */
    public record Enrolled(String account, String token) {
    }

    /** A new account, with the calling computer as its first client. */
    @PostMapping("/accounts")
    public Enrolled createAccount(@RequestBody NewClient request) {
        if (!props.openRegistration()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "this server doesn't accept new accounts");
        }
        Accounts.Enrolled enrolled = accounts.create(clientName(request.client()));
        return new Enrolled(enrolled.accountId(), enrolled.token());
    }

    /** @param code shown next to the request on the phone, so it can be matched to the terminal */
    public record JoinRequest(String client, String code) {
    }

    /**
     * Asks to add the calling computer to an account. Waits until the request is accepted (200 with
     * the computer's token), denied (403) or not answered in time (408) on the phone.
     */
    @PostMapping("/accounts/{account}/clients")
    public DeferredResult<ResponseEntity<?>> join(@PathVariable String account, @RequestBody JoinRequest request,
                                                  HttpServletRequest http) {
        String code = request.code() == null ? "" : request.code().strip();
        if (code.length() > 20 || code.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("invalid code");
        }
        CompletableFuture<Accounts.Enrolled> result;
        try {
            result = joins.request(account, clientName(request.client()), code, http.getRemoteAddr());
        } catch (NoSuchElementException e) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, e.getMessage());
        } catch (IllegalStateException e) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, e.getMessage());
        }
        DeferredResult<ResponseEntity<?>> response = new DeferredResult<>();
        response.onError(e -> result.cancel(false));
        result.whenComplete((enrolled, error) -> response.setResult(switch (error) {
            case null -> ResponseEntity.ok(new Enrolled(enrolled.accountId(), enrolled.token()));
            case SignService.DeniedException e -> ResponseEntity.status(HttpStatus.FORBIDDEN).body(e.getMessage());
            case TimeoutException e -> ResponseEntity.status(HttpStatus.REQUEST_TIMEOUT).body("not answered on the phone in time");
            case CancellationException e -> ResponseEntity.status(HttpStatus.GONE).build();
            default -> ResponseEntity.internalServerError().build();
        }));
        return response;
    }

    public record Account(String account) {
    }

    /** The account this computer belongs to. */
    @GetMapping("/account")
    public Account account(Principal principal) {
        return new Account(principal.getName());
    }

    public record EnrollLink(String url, Instant expiresAt) {
    }

    /** A single-use sign-in link for the phone, used to register a (first or additional) passkey. */
    @PostMapping("/enroll")
    public EnrollLink enroll(Principal principal) {
        OneTimeToken token = oneTimeTokens.generate(
                new GenerateOneTimeTokenRequest(principal.getName(), ENROLL_LINK_VALIDITY));
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
    public List<AgentKey> keys(Principal principal) {
        return sshKeys.findAll(principal.getName()).stream()
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
    public DeferredResult<ResponseEntity<?>> sign(@RequestBody SignRequest request, Principal principal) {
        if (request.publicKey() == null || request.data() == null) {
            throw new IllegalArgumentException("publicKey and data are required");
        }
        if (request.data().length > SignService.MAX_DATA_LENGTH) {
            throw new IllegalArgumentException("data too long");
        }
        SshKey key = sshKeys.findByPublicKey(principal.getName(), request.publicKey())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "unknown key"));
        CompletableFuture<byte[]> result = signs.request(key, request.data(), request.flags(), request.binding(),
                clientName(request.client()));

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

    private static String clientName(String name) {
        String client = name == null ? "" : name.strip().replaceAll("\\p{Cntrl}", "");
        if (client.isEmpty()) {
            return "cli";
        }
        return client.length() > 100 ? client.substring(0, 100) : client;
    }

    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public String badRequest(IllegalArgumentException e) {
        return e.getMessage();
    }
}
