package com.maykelange.ssha.server;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import com.jayway.jsonpath.JsonPath;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpServer;

@SpringBootTest(properties = {
        "ssha.rp-id=localhost",
        "ssha.vapid-key-file=",
        "ssha.allowed-origins=http://localhost",
        "spring.datasource.url=jdbc:h2:mem:ssha-push-test;DB_CLOSE_DELAY=-1",
})
@AutoConfigureMockMvc
class PushTest {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    @Autowired
    MockMvc mvc;
    @Autowired
    PushService push;
    @Autowired
    Accounts accounts;
    @Autowired
    JoinService joins;

    String account;
    KeyPair browser;
    byte[] browserPublic;
    byte[] auth = new byte[16];

    /** A stand-in push service: records what it receives, answers with {@link #status}. */
    HttpServer pushService;
    final List<Received> received = new CopyOnWriteArrayList<>();
    volatile int status = 201;

    record Received(String path, Headers headers, byte[] body) {
    }

    @BeforeEach
    void setUp() throws Exception {
        account = accounts.create("laptop").accountId();
        browser = WebPush.generateKeyPair();
        browserPublic = WebPush.rawPublicKey((ECPublicKey) browser.getPublic());
        auth[0] = 42;
        pushService = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        pushService.createContext("/", exchange -> {
            received.add(new Received(exchange.getRequestURI().getPath(), exchange.getRequestHeaders(),
                    exchange.getRequestBody().readAllBytes()));
            exchange.sendResponseHeaders(status, -1);
            exchange.close();
        });
        pushService.start();
    }

    @AfterEach
    void stop() {
        pushService.stop(0);
    }

    @Test
    void pwaFilesArePublic() throws Exception {
        mvc.perform(get("/manifest.webmanifest"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("\"display\": \"standalone\"")));
        mvc.perform(get("/sw.js")).andExpect(status().isOk());
        mvc.perform(get("/push.js")).andExpect(status().isOk());
        mvc.perform(get("/icon-192.png")).andExpect(status().isOk()).andExpect(header().string("Content-Type", "image/png"));
        mvc.perform(get("/login"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("rel=\"manifest\"")));
    }

    @Test
    void startPageCarriesTheServersPushKey() throws Exception {
        mvc.perform(get("/").with(user(account)))
                .andExpect(content().string(org.hamcrest.Matchers.containsString(
                        "<meta name=\"vapid-key\" content=\"" + push.publicKey() + "\">")));
    }

    @Test
    void onlyKnownPushServicesCanBeSubscribed() throws Exception {
        String fcm = "https://fcm.googleapis.com/fcm/send/abc";
        subscribe(fcm).andExpect(status().isNoContent());
        assertThat(push.subscriptions(account)).extracting(PushService.Subscription::endpoint).containsExactly(fcm);

        subscribe("https://web.push.apple.com/xyz").andExpect(status().isNoContent());
        subscribe("http://fcm.googleapis.com/fcm/send/abc").andExpect(status().isBadRequest());
        subscribe("https://evil.example/fcm.googleapis.com").andExpect(status().isBadRequest());
        subscribe("https://notfcm.googleapis.com.evil.example/x").andExpect(status().isBadRequest());
        subscribe("http://127.0.0.1:8080/admin").andExpect(status().isBadRequest());
        mvc.perform(post("/push/subscribe").with(user(account)).with(csrf()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"endpoint\":\"" + fcm + "\",\"keys\":{\"p256dh\":\"AAAA\",\"auth\":\"AAAA\"}}"))
                .andExpect(status().isBadRequest());
        mvc.perform(post("/push/subscribe").with(user(account)).contentType(MediaType.APPLICATION_JSON)
                        .content(subscriptionJson(fcm)))
                .andExpect(status().isForbidden());

        // Another account can't remove it; this one can.
        String other = accounts.create("x").accountId();
        mvc.perform(post("/push/unsubscribe").with(user(other)).with(csrf()).contentType(MediaType.APPLICATION_JSON)
                .content("{\"endpoint\":\"" + fcm + "\"}")).andExpect(status().isNoContent());
        assertThat(push.subscriptions(account)).hasSize(2);
        mvc.perform(post("/push/unsubscribe").with(user(account)).with(csrf()).contentType(MediaType.APPLICATION_JSON)
                .content("{\"endpoint\":\"" + fcm + "\"}")).andExpect(status().isNoContent());
        assertThat(push.subscriptions(account)).hasSize(1);
    }

    @Test
    void requestsArePushedEncryptedToTheAccountsBrowsers() throws Exception {
        String endpoint = "http://127.0.0.1:" + pushService.getAddress().getPort() + "/send/1";
        push.save(new PushService.Subscription(endpoint, account, browserPublic, auth));

        var waiting = joins.request(account, "desktop", "123 456", "192.0.2.7");
        assertThat(waitForPush().path()).isEqualTo("/send/1");
        Received r = received.getFirst();
        assertThat(r.headers().getFirst("Content-Encoding")).isEqualTo("aes128gcm");
        assertThat(r.headers().getFirst("TTL")).isEqualTo("120");
        assertThat(r.headers().getFirst("Urgency")).isEqualTo("high");
        assertThat(r.headers().getFirst("Authorization")).startsWith("vapid t=").endsWith(", k=" + push.publicKey());

        String message = new String(WebPushTest.decrypt(r.body(), browser.getPrivate(), browserPublic, auth),
                StandardCharsets.UTF_8);
        assertThat((String) JsonPath.read(message, "$.title")).isEqualTo("New computer");
        assertThat((String) JsonPath.read(message, "$.body"))
                .isEqualTo("desktop (192.0.2.7) wants to join this account, code 123 456");
        assertThat((String) JsonPath.read(message, "$.tag")).startsWith("join-");
        waiting.cancel(false);

        // Other accounts' requests don't reach this browser.
        String other = accounts.create("x").accountId();
        joins.request(other, "y", "", "192.0.2.8").cancel(false);
        push.notify(other, new PushService.Notification("t", "b", "x", Duration.ofSeconds(1))).get(5, TimeUnit.SECONDS);
        assertThat(received).hasSize(1);
    }

    @Test
    void theRequestCardRidesAlongWhenItFits() throws Exception {
        String endpoint = "http://127.0.0.1:" + pushService.getAddress().getPort() + "/send/3";
        push.save(new PushService.Subscription(endpoint, account, browserPublic, auth));

        push.notify(account, new PushService.Notification("t", "b", "x", Duration.ofSeconds(60), "<section id=\"sign-1\"></section>"))
                .get(5, TimeUnit.SECONDS);
        push.notify(account, new PushService.Notification("t", "b", "y", Duration.ofSeconds(60), "x".repeat(4000)))
                .get(5, TimeUnit.SECONDS);
        assertThat(received).hasSize(2);
        String small = new String(WebPushTest.decrypt(received.get(0).body(), browser.getPrivate(), browserPublic, auth),
                StandardCharsets.UTF_8);
        String big = new String(WebPushTest.decrypt(received.get(1).body(), browser.getPrivate(), browserPublic, auth),
                StandardCharsets.UTF_8);
        assertThat((String) JsonPath.read(small, "$.card")).isEqualTo("<section id=\"sign-1\"></section>");
        // Too big for one push message: the notification still goes out, the page gets the card from the stream.
        assertThat(big).doesNotContain("\"card\"");
    }

    @Test
    void goneSubscriptionsAreDropped() throws Exception {
        String endpoint = "http://127.0.0.1:" + pushService.getAddress().getPort() + "/send/2";
        push.save(new PushService.Subscription(endpoint, account, browserPublic, auth));
        status = 410;
        push.notify(account, new PushService.Notification("t", "b", "x", Duration.ofSeconds(60))).get(5, TimeUnit.SECONDS);
        assertThat(received).hasSize(1);
        assertThat(push.subscriptions(account)).isEmpty();
    }

    // --- helpers -----------------------------------------------------------------------------

    private Received waitForPush() throws InterruptedException {
        for (int i = 0; i < 100 && received.isEmpty(); i++) {
            Thread.sleep(50);
        }
        assertThat(received).isNotEmpty();
        return received.getFirst();
    }

    private org.springframework.test.web.servlet.ResultActions subscribe(String endpoint) throws Exception {
        return mvc.perform(post("/push/subscribe").with(user(account)).with(csrf())
                .contentType(MediaType.APPLICATION_JSON).content(subscriptionJson(endpoint)));
    }

    private String subscriptionJson(String endpoint) {
        return "{\"endpoint\":\"%s\",\"expirationTime\":null,\"keys\":{\"p256dh\":\"%s\",\"auth\":\"%s\"}}"
                .formatted(endpoint, B64URL.encodeToString(browserPublic), B64URL.encodeToString(auth));
    }
}
