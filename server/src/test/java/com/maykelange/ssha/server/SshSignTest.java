package com.maykelange.ssha.server;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.jayway.jsonpath.JsonPath;

@SpringBootTest(properties = {
        "ssha.rp-id=localhost",
        "ssha.allowed-origins=http://localhost",
        "spring.datasource.url=jdbc:h2:mem:ssha-sign-test;DB_CLOSE_DELAY=-1",
})
@AutoConfigureMockMvc
class SshSignTest {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    @Autowired
    MockMvc mvc;
    @Autowired
    SignService signs;
    @Autowired
    JdbcTemplate jdbc;
    @Autowired
    Accounts accounts;

    String account;
    String bearer;

    KeyPair phoneKey;
    byte[] publicBlob;

    @BeforeEach
    void createKeyOnThePhone() throws Exception {
        jdbc.update("delete from ssh_keys");
        Accounts.Enrolled enrolled = accounts.create("laptop");
        account = enrolled.accountId();
        bearer = "Bearer " + enrolled.token();
        phoneKey = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] encoded = phoneKey.getPublic().getEncoded();
        byte[] raw = Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length);
        publicBlob = SshWire.ed25519Blob(raw);

        mvc.perform(post("/keys").with(user(account)).with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"label\":\"phone\",\"publicKey\":\"" + B64URL.encodeToString(publicBlob) + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(SshWire.keyId(publicBlob)))
                .andExpect(jsonPath("$.authorizedKey").value(org.hamcrest.Matchers.startsWith("ssh-ed25519 AAAA")));
    }

    @Test
    void importingAKeyThatExistsKeepsTheEntry() throws Exception {
        mvc.perform(post("/keys").with(user(account)).with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"label\":\"other name\",\"publicKey\":\"" + B64URL.encodeToString(publicBlob) + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(SshWire.keyId(publicBlob)));
        mvc.perform(get("/api/keys").header("Authorization", bearer))
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].label").value("phone"));
        mvc.perform(post("/keys").with(user(account)).with(csrf())
                        .contentType(MediaType.APPLICATION_JSON).content("{\"label\":\"x\",\"publicKey\":\"AAAA\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void rsaKeySignsWithTheHashSshAskedFor() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(3072);
        KeyPair rsa = generator.generateKeyPair();
        RSAPublicKey pub = (RSAPublicKey) rsa.getPublic();
        byte[] blob = new SshWire.Writer().string("ssh-rsa").string(pub.getPublicExponent().toByteArray())
                .string(pub.getModulus().toByteArray()).toByteArray();
        mvc.perform(post("/keys").with(user(account)).with(csrf()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"label\":\"old laptop\",\"publicKey\":\"" + B64URL.encodeToString(blob) + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.authorizedKey").value(org.hamcrest.Matchers.startsWith("ssh-rsa AAAA")));
        mvc.perform(get("/keys").with(user(account)))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("RSA 3072")));

        byte[] data = "sign me".getBytes(StandardCharsets.UTF_8);
        for (var c : new String[][] {{"2", "rsa-sha2-256", "SHA256withRSA", "SHA-256"}, {"4", "rsa-sha2-512", "SHA512withRSA", "SHA-512"}}) {
            MvcResult pending = mvc.perform(post("/api/sign").header("Authorization", bearer)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(signJson(blob, data, null).replace("\"flags\":0", "\"flags\":" + c[0])))
                    .andExpect(request().asyncStarted())
                    .andReturn();
            assertThat(onlyPending().hash()).isEqualTo(c[3]);
            mvc.perform(post("/sign/" + onlyPending().id() + "/approve").with(user(account)).with(csrf())
                            .param("signature", B64URL.encodeToString(sign(rsa.getPrivate(), c[2], data))))
                    .andExpect(status().isNoContent());
            String body = mvc.perform(asyncDispatch(pending)).andExpect(status().isOk())
                    .andReturn().getResponse().getContentAsString();
            byte[] signature = Base64.getDecoder().decode((String) JsonPath.read(body, "$.signature"));
            assertThat(SshWire.algorithm(signature)).isEqualTo(c[1]);
            assertThat(SshWire.verify(blob, data, signature)).isTrue();
        }

        // Legacy SHA-1 "ssh-rsa" signatures are refused up front.
        mvc.perform(post("/api/sign").header("Authorization", bearer).contentType(MediaType.APPLICATION_JSON)
                        .content(signJson(blob, data, null)))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("SHA-1")));
        assertThat(signs.pending(account)).isEmpty();
    }

    @Test
    void shortRsaKeysAreRefused() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        RSAPublicKey pub = (RSAPublicKey) generator.generateKeyPair().getPublic();
        byte[] blob = new SshWire.Writer().string("ssh-rsa").string(pub.getPublicExponent().toByteArray())
                .string(pub.getModulus().toByteArray()).toByteArray();
        mvc.perform(post("/keys").with(user(account)).with(csrf()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"label\":\"old\",\"publicKey\":\"" + B64URL.encodeToString(blob) + "\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string("RSA keys need at least 2048 bits"));
    }

    @Test
    void agentListsThePhonesKeys() throws Exception {
        mvc.perform(get("/api/keys").header("Authorization", bearer))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].label").value("phone"))
                .andExpect(jsonPath("$[0].publicKey").value(Base64.getEncoder().encodeToString(publicBlob)));
        mvc.perform(get("/api/keys")).andExpect(status().isUnauthorized());
    }

    @Test
    void approvedSignatureIsRelayedToTheAgent() throws Exception {
        byte[] data = "ssh wants this signed".getBytes(StandardCharsets.UTF_8);
        MvcResult pending = startSign(data, null);
        String id = onlyPending().id();

        mvc.perform(post("/sign/" + id + "/approve").with(user(account)).with(csrf())
                        .param("signature", B64URL.encodeToString(sign(phoneKey.getPrivate(), "Ed25519", data))))
                .andExpect(status().isNoContent());

        String body = mvc.perform(asyncDispatch(pending))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        byte[] signature = Base64.getDecoder().decode((String) JsonPath.read(body, "$.signature"));
        assertThat(SshWire.verify(publicBlob, data, signature)).isTrue();
        assertThat(signs.pending(account)).isEmpty();
    }

    @Test
    void wrongSignatureIsRejectedAndRequestStaysOpen() throws Exception {
        byte[] data = "data".getBytes(StandardCharsets.UTF_8);
        MvcResult pending = startSign(data, null);
        String id = onlyPending().id();
        KeyPair other = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();

        mvc.perform(post("/sign/" + id + "/approve").with(user(account)).with(csrf())
                        .param("signature", B64URL.encodeToString(sign(other.getPrivate(), "Ed25519", data))))
                .andExpect(status().isBadRequest());
        assertThat(signs.pending(account)).hasSize(1);

        mvc.perform(post("/sign/" + id + "/deny").with(user(account)).with(csrf()))
                .andExpect(status().isNoContent());
        mvc.perform(asyncDispatch(pending)).andExpect(status().isForbidden());
        assertThat(signs.pending(account)).isEmpty();
    }

    @Test
    void answeringNeedsSessionAndCsrf() throws Exception {
        startSign(new byte[] {1, 2, 3}, null);
        String id = onlyPending().id();
        mvc.perform(post("/sign/" + id + "/deny").with(csrf()).header("HX-Request", "true"))
                .andExpect(status().isUnauthorized());
        mvc.perform(post("/sign/" + id + "/deny").with(user(account))).andExpect(status().isForbidden());
        mvc.perform(post("/sign/" + id + "/deny").header("Authorization", bearer)).andExpect(status().isForbidden());
        mvc.perform(post("/sign/" + id + "/deny").with(user(account)).with(csrf()))
                .andExpect(status().isNoContent());
        mvc.perform(post("/sign/" + id + "/deny").with(user(account)).with(csrf()))
                .andExpect(status().isNotFound());
    }

    @Test
    void unknownKeyIsRefusedImmediately() throws Exception {
        KeyPair other = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] encoded = other.getPublic().getEncoded();
        byte[] blob = SshWire.ed25519Blob(Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length));
        mvc.perform(post("/api/sign").header("Authorization", bearer).contentType(MediaType.APPLICATION_JSON)
                        .content(signJson(blob, new byte[] {1}, null)))
                .andExpect(status().isNotFound());
    }

    @Test
    void loginToVerifiedHostIsShownWithUserAndHostKey() throws Exception {
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        ec.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair host = ec.generateKeyPair();
        byte[] hostBlob = ecdsaBlob((ECPublicKey) host.getPublic());
        byte[] sessionId = new byte[32];
        Arrays.fill(sessionId, (byte) 7);
        byte[] hostSignature = new SshWire.Writer().string("ecdsa-sha2-nistp256")
                .string(ecdsaSignature(sign(host.getPrivate(), "SHA256withECDSAinP1363Format", sessionId)))
                .toByteArray();
        byte[] data = userAuth(sessionId, "git", publicBlob, hostBlob);

        startSign(data, new SignService.Binding(hostBlob, sessionId, hostSignature, false));
        SignDetails details = onlyPending().details();
        assertThat(details.kind()).isEqualTo("SSH login");
        assertThat(details.user()).isEqualTo("git");
        assertThat(details.hostKey()).isEqualTo(SshWire.fingerprint(hostBlob));
        assertThat(details.hostVerified()).isTrue();
        assertThat(details.warning()).isNull();
        signs.deny(account, onlyPending().id());

        // A binding for another session (or a forged host signature) is flagged.
        byte[] otherSession = new byte[32];
        startSign(userAuth(otherSession, "git", publicBlob, hostBlob),
                new SignService.Binding(hostBlob, sessionId, hostSignature, false));
        assertThat(onlyPending().details().hostVerified()).isFalse();
        assertThat(onlyPending().details().warning()).contains("does not match");
        signs.deny(account, onlyPending().id());
    }

    @Test
    void sshsigAndUnknownDataAreDescribed() {
        byte[] sshsig = concat("SSHSIG".getBytes(StandardCharsets.US_ASCII), new SshWire.Writer()
                .string("git").string(new byte[0]).string("sha512").string(new byte[64]).toByteArray());
        SignDetails git = SignDetails.describe(publicBlob, sshsig, null);
        assertThat(git.kind()).isEqualTo("Signature");
        assertThat(git.namespace()).isEqualTo("git");
        assertThat(git.warning()).isNull();

        SignDetails unknown = SignDetails.describe(publicBlob, new byte[] {1, 2, 3}, null);
        assertThat(unknown.kind()).isEqualTo("Unknown data");
        assertThat(unknown.warning()).isNotNull();
    }

    @Test
    void keysPageShowsAuthorizedKeysLine() throws Exception {
        mvc.perform(get("/keys").with(user(account)))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString(
                        "ssh-ed25519 " + Base64.getEncoder().encodeToString(publicBlob) + " ssha:phone")));
        mvc.perform(get("/keys")).andExpect(status().isFound());
    }

    // --- helpers -----------------------------------------------------------------------------

    private MvcResult startSign(byte[] data, SignService.Binding binding) throws Exception {
        return mvc.perform(post("/api/sign").header("Authorization", bearer).contentType(MediaType.APPLICATION_JSON)
                        .content(signJson(publicBlob, data, binding)))
                .andExpect(request().asyncStarted())
                .andReturn();
    }

    private SignService.Pending onlyPending() {
        assertThat(signs.pending(account)).hasSize(1);
        return signs.pending(account).getFirst();
    }

    private static String signJson(byte[] key, byte[] data, SignService.Binding binding) {
        Base64.Encoder b64 = Base64.getEncoder();
        String bindingJson = binding == null ? "null" : "{\"hostKey\":\"%s\",\"sessionId\":\"%s\",\"signature\":\"%s\",\"forwarded\":%s}"
                .formatted(b64.encodeToString(binding.hostKey()), b64.encodeToString(binding.sessionId()),
                        b64.encodeToString(binding.signature()), binding.forwarded());
        return "{\"publicKey\":\"%s\",\"data\":\"%s\",\"flags\":0,\"client\":\"laptop\",\"binding\":%s}"
                .formatted(b64.encodeToString(key), b64.encodeToString(data), bindingJson);
    }

    private static byte[] sign(PrivateKey key, String algorithm, byte[] data) throws Exception {
        Signature s = Signature.getInstance(algorithm);
        s.initSign(key);
        s.update(data);
        return s.sign();
    }

    private static byte[] userAuth(byte[] sessionId, String user, byte[] userKey, byte[] hostKey) {
        byte[] head = new SshWire.Writer().string(sessionId).toByteArray();
        byte[] tail = new SshWire.Writer().string(user).string("ssh-connection")
                .string("publickey-hostbound-v00@openssh.com").toByteArray();
        byte[] rest = new SshWire.Writer().string("ssh-ed25519").string(userKey).string(hostKey).toByteArray();
        return concat(head, new byte[] {50}, tail, new byte[] {1}, rest);
    }

    private static byte[] ecdsaBlob(ECPublicKey key) {
        byte[] q = new byte[65];
        q[0] = 4;
        copyUnsigned(key.getW().getAffineX().toByteArray(), q, 1);
        copyUnsigned(key.getW().getAffineY().toByteArray(), q, 33);
        return new SshWire.Writer().string("ecdsa-sha2-nistp256").string("nistp256").string(q).toByteArray();
    }

    /** P1363 (r || s) to SSH's (mpint r, mpint s). */
    private static byte[] ecdsaSignature(byte[] p1363) {
        byte[] r = new java.math.BigInteger(1, Arrays.copyOfRange(p1363, 0, 32)).toByteArray();
        byte[] s = new java.math.BigInteger(1, Arrays.copyOfRange(p1363, 32, 64)).toByteArray();
        return new SshWire.Writer().string(r).string(s).toByteArray();
    }

    private static void copyUnsigned(byte[] value, byte[] target, int offset) {
        int start = value.length > 32 ? value.length - 32 : 0;
        int length = value.length - start;
        System.arraycopy(value, start, target, offset + 32 - length, length);
    }

    private static byte[] concat(byte[]... parts) {
        int length = 0;
        for (byte[] p : parts) {
            length += p.length;
        }
        byte[] out = new byte[length];
        int at = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, at, p.length);
            at += p.length;
        }
        return out;
    }
}
