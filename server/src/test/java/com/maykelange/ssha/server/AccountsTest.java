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

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.util.Arrays;
import java.util.Base64;

import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.jayway.jsonpath.JsonPath;

@SpringBootTest(properties = {
        "ssha.rp-id=localhost",
        "ssha.allowed-origins=http://localhost",
        "spring.datasource.url=jdbc:h2:mem:ssha-accounts-test;DB_CLOSE_DELAY=-1",
})
@AutoConfigureMockMvc
class AccountsTest {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    @Autowired
    MockMvc mvc;
    @Autowired
    JoinService joins;
    @Autowired
    SignService signs;
    @Autowired
    Accounts accounts;

    @Test
    void cliWithoutTokenCreatesAnAccount() throws Exception {
        String body = mvc.perform(post("/api/accounts").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"client\":\"laptop\"}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String account = JsonPath.read(body, "$.account");
        String token = JsonPath.read(body, "$.token");
        assertThat(account).hasSize(22);

        mvc.perform(get("/api/account").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.account").value(account));
        mvc.perform(get("/clients").with(user(account)))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("laptop")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("ssha-cli --account " + account)));
    }

    @Test
    void joiningNeedsTheAccountsPhone() throws Exception {
        Enrolled first = register("laptop");
        MvcResult waiting = startJoin(first.account(), "desktop");
        JoinService.Pending pending = onlyJoin(first.account());
        assertThat(pending.client()).isEqualTo("desktop");
        assertThat(pending.code()).isEqualTo("123 456");

        // Another account's phone can't answer it.
        Enrolled other = register("intruder");
        mvc.perform(post("/join/" + pending.id() + "/accept").with(user(other.account())).with(csrf()))
                .andExpect(status().isNotFound());

        mvc.perform(post("/join/" + pending.id() + "/accept").with(user(first.account())).with(csrf()))
                .andExpect(status().isNoContent());
        String body = mvc.perform(asyncDispatch(waiting)).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        assertThat((String) JsonPath.read(body, "$.account")).isEqualTo(first.account());
        String token = JsonPath.read(body, "$.token");
        assertThat(token).isNotEqualTo(first.token());
        mvc.perform(get("/api/account").header("Authorization", "Bearer " + token))
                .andExpect(jsonPath("$.account").value(first.account()));
        assertThat(joins.pending(first.account())).isEmpty();
    }

    @Test
    void deniedJoinGetsNoToken() throws Exception {
        Enrolled first = register("laptop");
        MvcResult waiting = startJoin(first.account(), "stranger");
        mvc.perform(post("/join/" + onlyJoin(first.account()).id() + "/deny").with(user(first.account())).with(csrf()))
                .andExpect(status().isNoContent());
        mvc.perform(asyncDispatch(waiting)).andExpect(status().isForbidden());
    }

    @Test
    void unknownAccountCannotBeJoined() throws Exception {
        mvc.perform(post("/api/accounts/nope/clients").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"client\":\"x\",\"code\":\"1\"}"))
                .andExpect(status().isNotFound());
    }

    @Test
    void pendingJoinsPerAccountAreLimited() throws Exception {
        Enrolled first = register("laptop");
        for (int i = 0; i < JoinService.MAX_PENDING_PER_ACCOUNT; i++) {
            startJoin(first.account(), "spam");
        }
        mvc.perform(post("/api/accounts/" + first.account() + "/clients").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"client\":\"spam\",\"code\":\"1\"}"))
                .andExpect(status().isTooManyRequests());
        joins.pending(first.account()).forEach(p -> joins.deny(first.account(), p.id()));
    }

    @Test
    void accountsDontSeeEachOthersKeysOrRequests() throws Exception {
        Enrolled alice = register("alice-laptop");
        Enrolled bob = register("bob-laptop");
        byte[] encoded = KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic().getEncoded();
        byte[] blob = SshWire.ed25519Blob(Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length));
        String newKey = "{\"label\":\"phone\",\"publicKey\":\"" + B64URL.encodeToString(blob) + "\"}";
        mvc.perform(post("/keys").with(user(alice.account())).with(csrf())
                        .contentType(MediaType.APPLICATION_JSON).content(newKey))
                .andExpect(status().isOk());

        mvc.perform(get("/api/keys").header("Authorization", "Bearer " + bob.token()))
                .andExpect(jsonPath("$.length()").value(0));
        mvc.perform(get("/keys").with(user(bob.account())))
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString(Base64.getEncoder().encodeToString(blob)))));
        // Bob's agent can't ask for signatures with Alice's key, nor can Bob import it.
        mvc.perform(post("/api/sign").header("Authorization", "Bearer " + bob.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"publicKey\":\"" + Base64.getEncoder().encodeToString(blob) + "\",\"data\":\"AQ==\",\"flags\":0}"))
                .andExpect(status().isNotFound());
        mvc.perform(post("/keys").with(user(bob.account())).with(csrf())
                        .contentType(MediaType.APPLICATION_JSON).content(newKey))
                .andExpect(status().isBadRequest());
        mvc.perform(post("/keys/" + SshWire.keyId(blob) + "/delete").with(user(bob.account())).with(csrf()))
                .andExpect(status().isNotFound());

        // Alice's request is invisible to Bob's phone.
        mvc.perform(post("/api/sign").header("Authorization", "Bearer " + alice.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"publicKey\":\"" + Base64.getEncoder().encodeToString(blob) + "\",\"data\":\"AQ==\",\"flags\":0}"))
                .andExpect(request().asyncStarted());
        assertThat(signs.pending(bob.account())).isEmpty();
        String id = signs.pending(alice.account()).getFirst().id();
        mvc.perform(post("/sign/" + id + "/deny").with(user(bob.account())).with(csrf()))
                .andExpect(status().isNotFound());
        mvc.perform(post("/sign/" + id + "/deny").with(user(alice.account())).with(csrf()))
                .andExpect(status().isNoContent());
    }

    @Test
    void removedComputerLosesAccess() throws Exception {
        Enrolled first = register("laptop");
        mvc.perform(get("/api/keys").header("Authorization", "Bearer " + first.token())).andExpect(status().isOk());
        String clientId = accounts.clients(first.account()).getFirst().id();
        mvc.perform(post("/clients/" + clientId + "/delete").with(user(first.account())).with(csrf()))
                .andExpect(status().isFound());
        mvc.perform(get("/api/keys").header("Authorization", "Bearer " + first.token())).andExpect(status().isUnauthorized());
    }

    @Test
    void singleUserDataBecomesOneAccount(@TempDir Path dir) throws Exception {
        JdbcDataSource dataSource = new JdbcDataSource();
        dataSource.setURL("jdbc:h2:mem:ssha-migration-test;DB_CLOSE_DELAY=-1");
        new ResourceDatabasePopulator(new ClassPathResource("schema.sql")).execute(dataSource);
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        jdbc.update("insert into user_entities (id, name, display_name) values ('handle', 'maykelange', 'maykelange')");
        jdbc.update("insert into ssh_keys (id, label, public_key, created) values ('k', 'phone', X'00', current_timestamp)");
        Path tokenFile = Files.writeString(dir.resolve("token"), "old-token\n");

        Accounts migrated = new Accounts(jdbc, new SshaProperties("localhost", null, true, tokenFile, null, null));
        String account = jdbc.queryForObject("select id from accounts", String.class);
        assertThat(jdbc.queryForObject("select name from user_entities", String.class)).isEqualTo(account);
        assertThat(jdbc.queryForObject("select account_id from ssh_keys", String.class)).isEqualTo(account);
        assertThat(migrated.authenticate("old-token")).get().extracting(Accounts.Client::accountId).isEqualTo(account);

        // Only once.
        new Accounts(jdbc, new SshaProperties("localhost", null, true, tokenFile, null, null));
        assertThat(jdbc.queryForObject("select count(*) from accounts", Integer.class)).isEqualTo(1);
    }

    // --- helpers -----------------------------------------------------------------------------

    record Enrolled(String account, String token) {
    }

    private Enrolled register(String client) throws Exception {
        String body = mvc.perform(post("/api/accounts").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"client\":\"" + client + "\"}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return new Enrolled(JsonPath.read(body, "$.account"), JsonPath.read(body, "$.token"));
    }

    private MvcResult startJoin(String account, String client) throws Exception {
        return mvc.perform(post("/api/accounts/" + account + "/clients").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"client\":\"" + client + "\",\"code\":\"123 456\"}"))
                .andExpect(request().asyncStarted())
                .andReturn();
    }

    private JoinService.Pending onlyJoin(String account) {
        assertThat(joins.pending(account)).hasSize(1);
        return joins.pending(account).getFirst();
    }
}
