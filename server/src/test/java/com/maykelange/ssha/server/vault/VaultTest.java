package com.maykelange.ssha.server.vault;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.sql.Timestamp;
import java.time.Instant;
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
import org.springframework.test.web.servlet.ResultActions;

import com.jayway.jsonpath.JsonPath;

import com.maykelange.ssha.server.account.Accounts;
import com.maykelange.ssha.server.ssh.SshWire;

@SpringBootTest(properties = {
        "ssha.rp-id=localhost",
        "ssha.vapid-key-file=",
        "ssha.allowed-origins=http://localhost",
        "spring.datasource.url=jdbc:h2:mem:ssha-vault-test;DB_CLOSE_DELAY=-1",
})
@AutoConfigureMockMvc
class VaultTest {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    @Autowired
    MockMvc mvc;
    @Autowired
    Accounts accounts;
    @Autowired
    JdbcTemplate jdbc;

    String account;
    String phone;
    String laptop;

    @BeforeEach
    void createAccount() {
        account = accounts.create();
        phone = passkey(account);
        laptop = passkey(account);
    }

    @Test
    void theFirstSlotCreatesTheVaultAndLaterOnesJoinIt() throws Exception {
        vault(account).andExpect(jsonPath("$.salt").value(B64URL.encodeToString(VaultSlots.salt(account))))
                .andExpect(jsonPath("$.slots.length()").value(0));

        addSlot(phone, false).andExpect(status().isConflict());
        addSlot(phone, true).andExpect(status().isNoContent());
        // A second device can't start a vault of its own, nor replace a slot.
        addSlot(laptop, true).andExpect(status().isConflict());
        addSlot(laptop, false).andExpect(status().isNoContent());
        addSlot(laptop, false).andExpect(status().isConflict());

        vault(account).andExpect(jsonPath("$.slots[*].credentialId").value(
                org.hamcrest.Matchers.containsInAnyOrder(phone, laptop)));
    }

    @Test
    void onlyTheAccountsOwnPasskeysGetSlots() throws Exception {
        String stranger = passkey(accounts.create());
        addSlot(stranger, true).andExpect(status().isNotFound());
    }

    @Test
    void deletingAPasskeyDeletesItsSlot() throws Exception {
        addSlot(phone, true).andExpect(status().isNoContent());
        addSlot(laptop, false).andExpect(status().isNoContent());
        mvc.perform(post("/passkeys/" + laptop + "/delete").with(user(account)).with(csrf()))
                .andExpect(status().isFound());
        vault(account).andExpect(jsonPath("$.slots[*].credentialId").value(org.hamcrest.Matchers.contains(phone)));
    }

    @Test
    void encryptedKeysAreKeptAndListed() throws Exception {
        byte[] blob = ed25519Blob();
        String body = "{\"label\":\"phone\",\"publicKey\":\"" + B64URL.encodeToString(blob) + "\",\"iv\":\""
                + B64URL.encodeToString(new byte[12]) + "\",\"data\":\"" + B64URL.encodeToString(new byte[64]) + "\"}";
        mvc.perform(post("/keys").with(user(account)).with(csrf()).contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk());
        vault(account).andExpect(jsonPath("$.keys[0].id").value(SshWire.keyId(blob)))
                .andExpect(jsonPath("$.keys[0].type").value("ssh-ed25519"))
                .andExpect(jsonPath("$.keys[0].data").value(B64URL.encodeToString(new byte[64])));
        vault(accounts.create()).andExpect(jsonPath("$.keys.length()").value(0));
    }

    @Test
    void aDeviceGetsTheVaultKeyFromAnotherOne() throws Exception {
        addSlot(phone, true).andExpect(status().isNoContent());

        byte[] deviceKey = ecdhPublicKey();
        String id = requestKeys(laptop, deviceKey).andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(VaultJoins.code(deviceKey)))
                .andReturn().getResponse().getContentAsString();
        id = JsonPath.read(id, "$.id");
        assertThat(VaultJoins.code(deviceKey)).matches("\\d{3} \\d{3}");

        mvc.perform(get("/vault/devices/" + id).with(user(account))).andExpect(status().isAccepted());
        // Another account can neither see nor answer it.
        String other = accounts.create();
        mvc.perform(get("/vault/devices/" + id).with(user(other))).andExpect(status().isNotFound());
        approve(other, id).andExpect(status().isNotFound());

        approve(account, id).andExpect(status().isNoContent());
        mvc.perform(get("/vault/devices/" + id).with(user(account))).andExpect(status().isOk())
                .andExpect(jsonPath("$.data").value(B64URL.encodeToString(new byte[48])));

        addSlot(laptop, false).andExpect(status().isNoContent());
        mvc.perform(get("/vault/devices/" + id).with(user(account))).andExpect(status().isNotFound());
        // It has the key now.
        requestKeys(laptop, ecdhPublicKey()).andExpect(status().isConflict());
    }

    @Test
    void aDeniedDeviceIsTold() throws Exception {
        addSlot(phone, true).andExpect(status().isNoContent());
        String id = JsonPath.read(requestKeys(laptop, ecdhPublicKey()).andReturn().getResponse().getContentAsString(), "$.id");
        mvc.perform(post("/vault/devices/" + id + "/deny").with(user(account)).with(csrf()))
                .andExpect(status().isNoContent());
        mvc.perform(get("/vault/devices/" + id).with(user(account))).andExpect(status().isForbidden());
        approve(account, id).andExpect(status().isNotFound());
    }

    @Test
    void requestsNeedAVaultAndAProperKey() throws Exception {
        requestKeys(laptop, ecdhPublicKey()).andExpect(status().isConflict());
        addSlot(phone, true).andExpect(status().isNoContent());
        requestKeys(laptop, new byte[33]).andExpect(status().isBadRequest());
        requestKeys(passkey(accounts.create()), ecdhPublicKey()).andExpect(status().isNotFound());
    }

    // --- helpers ---------------------------------------------------------------------------------

    /** A passkey row for the account, as Spring Security's WebAuthn support would store it. */
    private String passkey(String accountId) {
        String userId = jdbc.query("select id from user_entities where name = ?", (rs, n) -> rs.getString(1), accountId)
                .stream().findFirst().orElseGet(() -> {
                    String id = B64URL.encodeToString(Accounts.randomId(16).getBytes());
                    jdbc.update("insert into user_entities (id, name, display_name) values (?, ?, ?)", id, accountId, accountId);
                    return id;
                });
        String credentialId = B64URL.encodeToString(Accounts.randomId(16).getBytes());
        jdbc.update("""
                insert into user_credentials (credential_id, user_entity_user_id, public_key, signature_count,
                    uv_initialized, backup_eligible, authenticator_transports, public_key_credential_type,
                    backup_state, created, last_used, label)
                values (?, ?, ?, 0, true, true, '', 'public-key', true, ?, ?, 'test')""",
                credentialId, userId, new byte[] {1}, Timestamp.from(Instant.now()), Timestamp.from(Instant.now()));
        return credentialId;
    }

    private ResultActions vault(String accountId) throws Exception {
        return mvc.perform(get("/vault").with(user(accountId))).andExpect(status().isOk());
    }

    private ResultActions addSlot(String credentialId, boolean create) throws Exception {
        String body = "{\"credentialId\":\"" + credentialId + "\",\"iv\":\"" + B64URL.encodeToString(new byte[12])
                + "\",\"wrapped\":\"" + B64URL.encodeToString(new byte[48]) + "\",\"create\":" + create + "}";
        return mvc.perform(post("/vault/slots").with(user(account)).with(csrf())
                .contentType(MediaType.APPLICATION_JSON).content(body));
    }

    private ResultActions requestKeys(String credentialId, byte[] publicKey) throws Exception {
        String body = "{\"credentialId\":\"" + credentialId + "\",\"publicKey\":\"" + B64URL.encodeToString(publicKey) + "\"}";
        return mvc.perform(post("/vault/devices").with(user(account)).with(csrf())
                .contentType(MediaType.APPLICATION_JSON).content(body));
    }

    private ResultActions approve(String accountId, String id) throws Exception {
        String body = "{\"ephemeralKey\":\"" + B64URL.encodeToString(ecdhPublicKey()) + "\",\"iv\":\""
                + B64URL.encodeToString(new byte[12]) + "\",\"data\":\"" + B64URL.encodeToString(new byte[48]) + "\"}";
        return mvc.perform(post("/vault/devices/" + id + "/approve").with(user(accountId)).with(csrf())
                .contentType(MediaType.APPLICATION_JSON).content(body));
    }

    /** An uncompressed P-256 point, as WebCrypto exports it ("raw"). */
    private static byte[] ecdhPublicKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        ECPublicKey key = (ECPublicKey) generator.generateKeyPair().getPublic();
        byte[] out = new byte[65];
        out[0] = 4;
        byte[] x = key.getW().getAffineX().toByteArray();
        byte[] y = key.getW().getAffineY().toByteArray();
        System.arraycopy(x, Math.max(0, x.length - 32), out, 1 + Math.max(0, 32 - x.length), Math.min(32, x.length));
        System.arraycopy(y, Math.max(0, y.length - 32), out, 33 + Math.max(0, 32 - y.length), Math.min(32, y.length));
        return out;
    }

    private static byte[] ed25519Blob() throws Exception {
        byte[] encoded = KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic().getEncoded();
        return SshWire.ed25519Blob(Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length));
    }
}
