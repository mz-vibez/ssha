package com.maykelange.ssha.cli;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
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


/**
 * Command-line side of ssha.
 *
 * <pre>
 *   ssha-cli                 set this computer up (see below) and show its account
 *   ssha-cli enroll          print a one-time sign-in link + QR code for adding a passkey on the phone
 *   ssha-cli agent           run an ssh-agent whose keys live on the phone (each use approved there)
 *   ssha-cli keys            print the phone's SSH public keys as authorized_keys lines
 * </pre>
 *
 * Each computer has its own API token, from $SSHA_TOKEN or {@code <project>/data/token}. Without one,
 * the CLI first gets one: with {@code --account ID} (or $SSHA_ACCOUNT) by asking to join that account,
 * which must be accepted on the account's phone; otherwise by creating a new account.
 *
 * The server URL comes from --url, $SSHA_URL, or defaults to https://ssha.apps.maykelange.com.
 */
public final class SshaCli {

    private static final String DEFAULT_URL = "https://ssha.apps.maykelange.com";
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm").withZone(ZoneId.systemDefault());
    private static final DateTimeFormatter TIME_SECONDS = DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());

    private static final Path TOKEN_FILE = dataDir().resolve("token");
    private static final Path AGENT_SOCKET = dataDir().resolve("agent.sock");

    record EnrollLink(String url, Instant expiresAt) {
    }

    record Enrolled(String account, String token) {
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
            super("the server rejected this computer's API token (HTTP 401); it may have been removed on the phone. "
                    + "Delete " + TOKEN_FILE + " and run ssha-cli --account <id> to join the account again");
        }
    }

    private final URI base;
    private String token;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();

    private SshaCli(String url, String token) {
        this.base = URI.create(url.endsWith("/") ? url : url + "/");
        this.token = token;
    }

    /**
     * Where the token and agent socket live: {@code <project>/data} when running from a checkout of the
     * project, otherwise (e.g. a CLI downloaded from the server) {@code $XDG_CONFIG_HOME/ssha}, by
     * default {@code ~/.config/ssha}.
     */
    static Path dataDir() {
        Path project = projectDir();
        if (project != null) {
            return project.resolve("data");
        }
        String config = System.getenv("XDG_CONFIG_HOME");
        // $HOME first, like other command-line tools; Java's user.home ignores it.
        String home = System.getenv("HOME");
        Path base = config != null && !config.isBlank()
                ? Path.of(config)
                : Path.of(home != null && !home.isBlank() ? home : System.getProperty("user.home"), ".config");
        return base.resolve("ssha");
    }

    /**
     * The project folder (the one holding {@code server/} and {@code cli/}), found by walking up from
     * the running jar or classes directory, or from the executable when running as a native image;
     * null when the CLI doesn't run from a checkout.
     */
    static Path projectDir() {
        String classPath = System.getProperty("java.class.path", "").split(java.io.File.pathSeparator)[0];
        Path start = classPath.isEmpty()
                ? ProcessHandle.current().info().command().map(Path::of).orElse(Path.of(""))
                : Path.of(classPath);
        for (Path dir = start.toAbsolutePath(); dir != null; dir = dir.getParent()) {
            if (Files.isRegularFile(dir.resolve("server/pom.xml")) && Files.isRegularFile(dir.resolve("cli/pom.xml"))) {
                return dir;
            }
        }
        return null;
    }

    /** This computer's token, or null if it has none yet. */
    private static String loadToken() throws IOException {
        String env = System.getenv("SSHA_TOKEN");
        if (env != null && !env.isBlank()) {
            return env.strip();
        }
        if (!Files.exists(TOKEN_FILE)) {
            return null;
        }
        String token = Files.readString(TOKEN_FILE).strip();
        return token.isEmpty() ? null : token;
    }

    private static void saveToken(String token) throws IOException {
        Files.createDirectories(TOKEN_FILE.getParent(),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        Path temp = Files.createTempFile(TOKEN_FILE.getParent(), "token", ".tmp",
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        Files.writeString(temp, token + "\n");
        Files.move(temp, TOKEN_FILE, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    private HttpRequest.Builder request(String path) {
        return HttpRequest.newBuilder(base.resolve(path)).header("Authorization", "Bearer " + token);
    }

    public static void main(String[] args) throws Exception {
        String url = System.getenv().getOrDefault("SSHA_URL", DEFAULT_URL);
        String account = System.getenv("SSHA_ACCOUNT");
        int i = 0;
        while (i + 1 < args.length && (args[i].equals("--url") || args[i].equals("--account"))) {
            if (args[i].equals("--url")) {
                url = args[i + 1];
            } else {
                account = args[i + 1];
            }
            i += 2;
        }
        String command = i < args.length ? args[i] : "";
        if (command.equals("-h") || command.equals("--help") || command.equals("help")) {
            usage();
            return;
        }
        if (account != null && account.isBlank()) {
            account = null;
        }
        if (!List.of("", "enroll", "agent", "keys").contains(command)) {
            usage();
            System.exit(2);
        }

        SshaCli cli = new SshaCli(url, loadToken());
        boolean setUp = false;
        if (cli.token == null) {
            if (!(account == null ? cli.createAccount() : cli.join(account))) {
                System.exit(1);
            }
            setUp = true;
        } else if (account != null && !cli.checkAccount(account)) {
            System.exit(1);
        }
        switch (command) {
            case "" -> System.exit(setUp || cli.printAccount() ? 0 : 1);
            case "enroll" -> System.exit(cli.enroll() ? 0 : 1);
            case "agent" -> cli.agent();
            case "keys" -> System.exit(cli.printKeys() ? 0 : 1);
            default -> throw new IllegalStateException(command);
        }
    }

    private static void usage() {
        System.out.println("""
                usage: ssha-cli [--url URL] [--account ID] [enroll | agent | keys]
                  (none)  set this computer up if needed, and show its account
                  enroll  one-time sign-in link + QR code to add a passkey on your phone
                  agent   ssh-agent backed by the phone: listens on %s,
                          every signature must be approved on the phone
                  keys    the phone's SSH public keys, as authorized_keys lines
                Without an API token, ssha-cli first creates a new account, or with --account ID
                (or $SSHA_ACCOUNT) asks to join that account, which you accept on its phone.
                Server URL: --url, $SSHA_URL, or %s
                API token:  $SSHA_TOKEN, or %s""".formatted(AGENT_SOCKET, DEFAULT_URL, TOKEN_FILE));
    }

    // --- accounts -------------------------------------------------------------------------------

    /** A new account with this computer in it, then a passkey for the phone. */
    private boolean createAccount() {
        try {
            HttpResponse<String> response = http.send(HttpRequest.newBuilder(base.resolve("api/accounts"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(Json.strings(Map.of("client", hostName()))))
                    .build(), HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                System.err.println("couldn't create an account: HTTP " + response.statusCode() + " " + response.body());
                return false;
            }
            Enrolled enrolled = Json.enrolled(response.body());
            saveToken(enrolled.token());
            token = enrolled.token();
            System.out.println("Created a new account; this computer's token is in " + TOKEN_FILE + ".");
            System.out.println();
            System.out.println("Account id: " + enrolled.account());
            System.out.println("To use it on another computer: ssha-cli --account " + enrolled.account());
            System.out.println();
            return enroll();
        } catch (IOException e) {
            System.err.println("couldn't create an account: " + e.getMessage());
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    /** Asks to add this computer to an existing account and waits for the phone to accept. */
    private boolean join(String account) {
        String code = "%03d %03d".formatted(RANDOM.nextInt(1000), RANDOM.nextInt(1000));
        System.out.println("Asking to join account " + account + ".");
        System.out.println("Accept the request on that account's phone; it shows the code " + code + ".");
        try {
            HttpResponse<String> response = http.send(HttpRequest.newBuilder(base.resolve(
                                    "api/accounts/" + URLEncoder.encode(account, StandardCharsets.UTF_8) + "/clients"))
                            .timeout(Duration.ofMinutes(5))
                            .header("Content-Type", "application/json")
                            .POST(HttpRequest.BodyPublishers.ofString(
                                    Json.strings(Map.of("client", hostName(), "code", code))))
                            .build(),
                    HttpResponse.BodyHandlers.ofString());
            switch (response.statusCode()) {
                case 200 -> {
                    Enrolled enrolled = Json.enrolled(response.body());
                    saveToken(enrolled.token());
                    token = enrolled.token();
                    System.out.println("Accepted; this computer's token is in " + TOKEN_FILE + ".");
                    return true;
                }
                case 403 -> System.err.println("Denied on the phone.");
                case 404 -> System.err.println("There is no account " + account + " on " + base + ".");
                case 408 -> System.err.println("Not answered on the phone in time; run the command again.");
                default -> System.err.println("couldn't join: HTTP " + response.statusCode() + " " + response.body());
            }
            return false;
        } catch (IOException e) {
            System.err.println("couldn't join: " + e.getMessage());
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private String fetchAccount() throws IOException, InterruptedException {
        HttpResponse<String> response = http.send(request("api/account").timeout(Duration.ofSeconds(15)).build(),
                HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 401) {
            throw new UnauthorizedException();
        }
        if (response.statusCode() != 200) {
            throw new IOException("HTTP " + response.statusCode());
        }
        return Json.account(response.body());
    }

    /** With a token already, --account only confirms which account that is. */
    private boolean checkAccount(String account) {
        try {
            String actual = fetchAccount();
            if (!actual.equals(account)) {
                System.err.println("This computer already belongs to account " + actual + ". To switch, delete "
                        + TOKEN_FILE + " and run the command again.");
                return false;
            }
            return true;
        } catch (IOException e) {
            System.err.println("couldn't check the account: " + e.getMessage());
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private boolean printAccount() {
        try {
            String account = fetchAccount();
            System.out.println("Account id: " + account);
            System.out.println("To use it on another computer: ssha-cli --account " + account);
            System.out.println("Run ssha-cli --help for the commands.");
            return true;
        } catch (IOException e) {
            System.err.println("couldn't get the account: " + e.getMessage());
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
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
            EnrollLink link = Json.enrollLink(response.body());
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
        List<AgentKey> keys = Json.agentKeys(response.body());
        keys.forEach(k -> keyLabels.put(HexFormat.of().formatHex(k.publicKey()), k.label()));
        return keys;
    }

    private byte[] requestSignature(SignRequest sign) throws IOException, InterruptedException {
        String label = keyLabels.getOrDefault(HexFormat.of().formatHex(sign.publicKey()), "unknown key");
        log("sign request for key '" + label + "', waiting for approval on the phone…");
        HttpRequest request = request("api/sign")
                .timeout(Duration.ofMinutes(5))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(Json.signRequest(sign)))
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        switch (response.statusCode()) {
            case 200 -> {
                log("approved");
                return Json.signResponse(response.body()).signature();
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
