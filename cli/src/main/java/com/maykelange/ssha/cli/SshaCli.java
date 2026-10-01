package com.maykelange.ssha.cli;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;

import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.json.JsonMapper;

/**
 * Command-line side of ssha.
 *
 * <pre>
 *   ssha-cli enroll          print a one-time sign-in link + QR code for adding a passkey on the phone
 *   ssha-cli agent           run an ssh-agent whose keys live on the phone (each use approved there)
 *   ssha-cli keys            print the phone's SSH public keys as authorized_keys lines
 * </pre>
 *
 * The server URL comes from --url, $SSHA_URL, or defaults to https://ssha.apps.maykelange.com.
 * The API token comes from $SSHA_TOKEN or {@code <project>/data/token} (the file the server generates).
 */
public final class SshaCli {

    private static final String DEFAULT_URL = "https://ssha.apps.maykelange.com";
    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm").withZone(ZoneId.systemDefault());
    private static final DateTimeFormatter TIME_SECONDS = DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());

    private static final Path TOKEN_FILE = projectDir().resolve("data").resolve("token");
    private static final Path AGENT_SOCKET = projectDir().resolve("data").resolve("agent.sock");

    record EnrollLink(String url, Instant expiresAt) {
    }

    record AgentKey(String id, String label, byte[] publicKey, String authorizedKey) {
    }

    record SignRequest(byte[] publicKey, byte[] data, int flags, String client, SshAgent.Binding binding) {
    }

    record SignResponse(byte[] signature) {
    }

    /** Thrown when the server rejects the token; retrying won't help. */
    static final class UnauthorizedException extends IOException {
        UnauthorizedException() {
            super("the server rejected the API token (HTTP 401). Set $SSHA_TOKEN or " + TOKEN_FILE
                    + " to the server's token");
        }
    }

    private final URI base;
    private final String token;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    private final JsonMapper json = JsonMapper.builder()
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();

    private SshaCli(String url, String token) {
        this.base = URI.create(url.endsWith("/") ? url : url + "/");
        this.token = token;
    }

    /**
     * The project folder (the one holding {@code server/} and {@code cli/}), found by walking up from
     * the running jar or classes directory; falls back to the working directory.
     */
    static Path projectDir() {
        String classPath = System.getProperty("java.class.path", "").split(java.io.File.pathSeparator)[0];
        for (Path dir = Path.of(classPath).toAbsolutePath(); dir != null; dir = dir.getParent()) {
            if (Files.isRegularFile(dir.resolve("server/pom.xml")) && Files.isRegularFile(dir.resolve("cli/pom.xml"))) {
                return dir;
            }
        }
        return Path.of("").toAbsolutePath();
    }

    private static String loadToken() {
        String env = System.getenv("SSHA_TOKEN");
        if (env != null && !env.isBlank()) {
            return env.strip();
        }
        try {
            return Files.readString(TOKEN_FILE).strip();
        } catch (IOException e) {
            System.err.println("No API token: set $SSHA_TOKEN or create " + TOKEN_FILE
                    + " (the server writes it there on first start).");
            System.exit(2);
            return null;
        }
    }

    private HttpRequest.Builder request(String path) {
        return HttpRequest.newBuilder(base.resolve(path)).header("Authorization", "Bearer " + token);
    }

    public static void main(String[] args) throws Exception {
        String url = System.getenv().getOrDefault("SSHA_URL", DEFAULT_URL);
        int i = 0;
        if (args.length >= 2 && args[0].equals("--url")) {
            url = args[1];
            i = 2;
        }
        String command = i < args.length ? args[i] : "help";
        if (command.equals("-h") || command.equals("--help") || command.equals("help")) {
            usage();
            return;
        }
        SshaCli cli = new SshaCli(url, loadToken());
        switch (command) {
            case "enroll" -> System.exit(cli.enroll() ? 0 : 1);
            case "agent" -> cli.agent();
            case "keys" -> System.exit(cli.printKeys() ? 0 : 1);
            default -> {
                usage();
                System.exit(2);
            }
        }
    }

    private static void usage() {
        System.out.println("""
                usage: ssha-cli [--url URL] (enroll | agent | keys)
                  enroll  one-time sign-in link + QR code to add a passkey on your phone
                  agent   ssh-agent backed by the phone: listens on %s,
                          every signature must be approved on the phone
                  keys    the phone's SSH public keys, as authorized_keys lines
                Server URL: --url, $SSHA_URL, or %s
                API token:  $SSHA_TOKEN, or %s""".formatted(AGENT_SOCKET, DEFAULT_URL, TOKEN_FILE));
    }

    private boolean enroll() {
        HttpRequest request = request("api/enroll").POST(HttpRequest.BodyPublishers.noBody()).build();
        try {
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 401) {
                throw new UnauthorizedException();
            }
            if (response.statusCode() != 200) {
                System.err.println("enroll failed: HTTP " + response.statusCode() + " " + response.body());
                return false;
            }
            EnrollLink link = json.readValue(response.body(), EnrollLink.class);
            System.out.println("Scan with your phone to sign in once and add a passkey:");
            System.out.println();
            System.out.print(qr(link.url()));
            System.out.println();
            System.out.println(link.url());
            System.out.println("Single use, valid until " + TIME.format(link.expiresAt()) + ".");
            return true;
        } catch (IOException e) {
            System.err.println("enroll failed: " + e.getMessage());
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    // --- SSH agent ------------------------------------------------------------------------------

    /** Key labels by public key (hex), for log lines. */
    private final Map<String, String> keyLabels = new ConcurrentHashMap<>();

    private void agent() throws IOException {
        String client = hostName();
        SshAgent agent = new SshAgent(new SshAgent.Phone() {
            @Override
            public List<SshAgent.Identity> identities() throws IOException, InterruptedException {
                return fetchKeys().stream()
                        .map(k -> new SshAgent.Identity(k.publicKey(), "ssha:" + k.label()))
                        .toList();
            }

            @Override
            public byte[] sign(byte[] publicKey, byte[] data, int flags, SshAgent.Binding binding)
                    throws IOException, InterruptedException {
                return requestSignature(new SignRequest(publicKey, data, flags, client, binding));
            }
        });
        agent.serve(AGENT_SOCKET, () -> {
            // Same shape as ssh-agent's output, so `eval` works on it.
            System.out.println("SSH_AUTH_SOCK=" + AGENT_SOCKET + "; export SSH_AUTH_SOCK;");
            System.out.flush();
            log("agent ready; sign requests go to " + base + " for approval. Ctrl-C to stop.");
        });
    }

    private List<AgentKey> fetchKeys() throws IOException, InterruptedException {
        HttpResponse<String> response = http.send(request("api/keys").timeout(Duration.ofSeconds(15)).build(),
                HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 401) {
            throw new UnauthorizedException();
        }
        if (response.statusCode() != 200) {
            throw new IOException("HTTP " + response.statusCode());
        }
        List<AgentKey> keys = Arrays.asList(json.readValue(response.body(), AgentKey[].class));
        keys.forEach(k -> keyLabels.put(HexFormat.of().formatHex(k.publicKey()), k.label()));
        return keys;
    }

    private byte[] requestSignature(SignRequest sign) throws IOException, InterruptedException {
        String label = keyLabels.getOrDefault(HexFormat.of().formatHex(sign.publicKey()), "unknown key");
        log("sign request for key '" + label + "', waiting for approval on the phone…");
        HttpRequest request = request("api/sign")
                .timeout(Duration.ofMinutes(5))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json.writeValueAsString(sign)))
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        switch (response.statusCode()) {
            case 200 -> {
                log("approved");
                return json.readValue(response.body(), SignResponse.class).signature();
            }
            case 401 -> throw new UnauthorizedException();
            case 403 -> log("denied on the phone");
            case 404 -> log("the server doesn't know this key");
            case 408 -> log("not answered on the phone in time");
            default -> log("sign request failed: HTTP " + response.statusCode() + " " + response.body());
        }
        return null;
    }

    private boolean printKeys() {
        try {
            List<AgentKey> keys = fetchKeys();
            if (keys.isEmpty()) {
                System.err.println("No SSH keys yet: create one on the phone (Keys page).");
            }
            for (AgentKey k : keys) {
                System.out.println(k.authorizedKey());
            }
            return true;
        } catch (IOException e) {
            System.err.println("couldn't list keys: " + e.getMessage());
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private static String hostName() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (IOException e) {
            return "cli";
        }
    }

    static void log(String line) {
        System.err.println("[" + TIME_SECONDS.format(Instant.now()) + "] " + line);
    }

    /**
     * Renders a QR code with half-block characters, two modules rows per text line. Colours are set
     * explicitly (black on white) so it scans on both dark and light terminals.
     */
    static String qr(String text) {
        BitMatrix m;
        try {
            m = new QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0,
                    Map.of(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.L, EncodeHintType.MARGIN, 2));
        } catch (WriterException e) {
            throw new IllegalStateException(e);
        }
        StringBuilder out = new StringBuilder();
        for (int y = 0; y < m.getHeight(); y += 2) {
            out.append("\u001b[30;47m");
            for (int x = 0; x < m.getWidth(); x++) {
                boolean top = m.get(x, y);
                boolean bottom = y + 1 < m.getHeight() && m.get(x, y + 1);
                out.append(top ? (bottom ? '█' : '▀') : (bottom ? '▄' : ' '));
            }
            out.append("\u001b[0m\n");
        }
        return out.toString();
    }
}
