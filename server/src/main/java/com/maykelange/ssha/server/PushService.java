package com.maykelange.ssha.server;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import tools.jackson.databind.json.JsonMapper;

/**
 * Web Push notifications to the phones of an account, so a sign or join request is noticed even
 * when the start page isn't open. A notification only says what is waiting; answering it still
 * happens on the start page.
 */
@Service
public class PushService {

    private static final Logger log = LoggerFactory.getLogger(PushService.class);
    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    /** Enough for every browser and home-screen app one person has. */
    static final int MAX_SUBSCRIPTIONS_PER_ACCOUNT = 20;

    /**
     * @param tag a request id: the phone replaces a notification with the same tag
     * @param ttl how long the push service should keep trying to deliver it
     * @param card the request's rendered card, so the phone can show it without any network; null if none
     */
    public record Notification(String title, String body, String tag, Duration ttl, String card) {
        public Notification(String title, String body, String tag, Duration ttl) {
            this(title, body, tag, ttl, null);
        }
    }

    /** Keeps the encrypted message within one push record (4096 bytes, minus the headers). */
    static final int MAX_PAYLOAD_WITH_CARD = 3500;

    record Subscription(String endpoint, String accountId, byte[] p256dh, byte[] auth) {
    }

    private final JdbcTemplate jdbc;
    private final SshaProperties props;
    private final KeyPair vapid;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();

    public PushService(JdbcTemplate jdbc, SshaProperties props) {
        this.jdbc = jdbc;
        this.props = props;
        this.vapid = loadOrCreate(props.vapidKeyFile());
    }

    /** The VAPID public key, base64url, for the page's {@code pushManager.subscribe()}. */
    public String publicKey() {
        return B64URL.encodeToString(WebPush.rawPublicKey((ECPublicKey) vapid.getPublic()));
    }

    /**
     * Adds (or moves to this account) a browser's push subscription.
     *
     * @throws IllegalArgumentException if the endpoint isn't a known push service, or the keys are invalid
     * @throws IllegalStateException    if the account has too many subscriptions
     */
    public void subscribe(String accountId, String endpoint, byte[] p256dh, byte[] auth) {
        URI uri;
        try {
            uri = URI.create(endpoint);
        } catch (IllegalArgumentException | NullPointerException e) {
            throw new IllegalArgumentException("invalid endpoint");
        }
        String host = uri.getHost();
        if (!"https".equals(uri.getScheme()) || host == null || endpoint.length() > 2000
                || props.pushHosts().stream().noneMatch(h -> host.equals(h) || host.endsWith("." + h))) {
            throw new IllegalArgumentException("not a known push service");
        }
        if (p256dh == null || auth == null || auth.length != 16) {
            throw new IllegalArgumentException("invalid subscription keys");
        }
        WebPush.publicKey(p256dh);
        int existing = jdbc.queryForObject(
                "select count(*) from push_subscriptions where account_id = ? and endpoint <> ?", Integer.class,
                accountId, endpoint);
        if (existing >= MAX_SUBSCRIPTIONS_PER_ACCOUNT) {
            throw new IllegalStateException("too many devices with notifications");
        }
        save(new Subscription(endpoint, accountId, p256dh, auth));
    }

    /** Stores a subscription as is; {@link #subscribe} checks it first. */
    void save(Subscription s) {
        jdbc.update("merge into push_subscriptions (endpoint, account_id, p256dh, auth, created) key (endpoint) "
                + "values (?, ?, ?, ?, ?)", s.endpoint(), s.accountId(), s.p256dh(), s.auth(), Timestamp.from(Instant.now()));
    }

    public void unsubscribe(String accountId, String endpoint) {
        jdbc.update("delete from push_subscriptions where account_id = ? and endpoint = ?", accountId, endpoint);
    }

    List<Subscription> subscriptions(String accountId) {
        return jdbc.query("select * from push_subscriptions where account_id = ?", (rs, n) -> new Subscription(
                rs.getString("endpoint"), rs.getString("account_id"), rs.getBytes("p256dh"), rs.getBytes("auth")),
                accountId);
    }

    /** Sends the notification to every subscription of the account, in the background. */
    public CompletableFuture<Void> notify(String accountId, Notification notification) {
        Map<String, Object> message = new LinkedHashMap<>();
        message.put("title", notification.title());
        message.put("body", notification.body());
        message.put("tag", notification.tag());
        message.put("at", Instant.now().toEpochMilli());
        byte[] payload = JSON.writeValueAsString(message).getBytes(StandardCharsets.UTF_8);
        if (notification.card() != null) {
            message.put("card", notification.card());
            byte[] withCard = JSON.writeValueAsString(message).getBytes(StandardCharsets.UTF_8);
            if (withCard.length <= MAX_PAYLOAD_WITH_CARD) {
                payload = withCard;
            }
        }
        byte[] body = payload;
        return CompletableFuture.allOf(subscriptions(accountId).stream()
                .map(s -> send(s, body, notification.ttl()))
                .toArray(CompletableFuture[]::new));
    }

    private CompletableFuture<Void> send(Subscription s, byte[] payload, Duration ttl) {
        URI endpoint = URI.create(s.endpoint());
        HttpRequest request = HttpRequest.newBuilder(endpoint)
                .timeout(Duration.ofSeconds(15))
                .header("Authorization", WebPush.vapidAuthorization(endpoint, vapid, props.vapidSubject(),
                        Instant.now().plus(Duration.ofHours(12))))
                .header("Content-Encoding", "aes128gcm")
                .header("Content-Type", "application/octet-stream")
                .header("TTL", Long.toString(Math.max(0, ttl.toSeconds())))
                .header("Urgency", "high")
                .POST(HttpRequest.BodyPublishers.ofByteArray(WebPush.encrypt(payload, s.p256dh(), s.auth())))
                .build();
        return http.sendAsync(request, HttpResponse.BodyHandlers.ofString()).handle((response, error) -> {
            if (error != null) {
                log.warn("Push to {} failed: {}", endpoint.getHost(), error.toString());
            } else if (response.statusCode() == 404 || response.statusCode() == 410) {
                // The browser dropped the subscription (unsubscribed, data cleared, app removed).
                jdbc.update("delete from push_subscriptions where endpoint = ?", s.endpoint());
            } else if (response.statusCode() / 100 != 2) {
                log.warn("Push to {} refused: HTTP {} {}", endpoint.getHost(), response.statusCode(), response.body());
            }
            return null;
        });
    }

    /**
     * The VAPID key pair: the push services know the server by it, and subscriptions are bound to it,
     * so it is kept in a file (two base64 lines: PKCS#8 private key, X.509 public key). Without a file
     * (tests) a fresh pair is used.
     */
    private static KeyPair loadOrCreate(Path file) {
        if (file == null || file.toString().isEmpty()) {
            return WebPush.generateKeyPair();
        }
        try {
            if (Files.exists(file)) {
                List<String> lines = Files.readAllLines(file);
                KeyFactory ec = KeyFactory.getInstance("EC");
                return new KeyPair(
                        ec.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(lines.get(1)))),
                        ec.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(lines.get(0)))));
            }
            KeyPair pair = WebPush.generateKeyPair();
            Files.createDirectories(file.getParent());
            Files.createFile(file, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
            Files.writeString(file, Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()) + "\n"
                    + Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()) + "\n");
            log.info("Generated the Web Push (VAPID) key in {}", file);
            return pair;
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot read or create " + file, e);
        } catch (GeneralSecurityException | RuntimeException e) {
            throw new IllegalStateException("Invalid VAPID key file " + file, e);
        }
    }
}
