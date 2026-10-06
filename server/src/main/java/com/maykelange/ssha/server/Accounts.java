package com.maykelange.ssha.server;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/**
 * Accounts and the computers (clients) allowed to use them. An account is created by the first
 * computer that runs {@code ssha-cli} without a token; further computers join it with its id and
 * need approval on the phone. Each client has its own bearer token, stored only as a SHA-256 hash.
 */
@Repository
public class Accounts {

    private static final Logger log = LoggerFactory.getLogger(Accounts.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final RowMapper<Client> CLIENT = (rs, n) -> new Client(rs.getString("id"),
            rs.getString("account_id"), rs.getString("name"), rs.getTimestamp("created").toInstant(),
            Optional.ofNullable(rs.getTimestamp("last_used")).map(Timestamp::toInstant).orElse(null));

    /** A computer allowed to use an account. */
    public record Client(String id, String accountId, String name, Instant created, Instant lastUsed) {
    }

    /** A new client and the bearer token it authenticates with (only ever returned once). */
    public record Enrolled(String accountId, Client client, String token) {
    }

    private final JdbcTemplate jdbc;

    public Accounts(JdbcTemplate jdbc, SshaProperties props) {
        this.jdbc = jdbc;
        migrateSingleUserData(props.legacyTokenFile());
    }

    /** A new account with {@code clientName} as its first, already trusted, client. */
    @Transactional
    public Enrolled create(String clientName) {
        String id = randomId(16);
        jdbc.update("insert into accounts (id, created) values (?, ?)", id, Timestamp.from(Instant.now()));
        return addClient(id, clientName);
    }

    public boolean exists(String accountId) {
        return accountId != null && !jdbc.queryForList("select id from accounts where id = ?", String.class, accountId).isEmpty();
    }

    public Enrolled addClient(String accountId, String name) {
        String token = randomId(32);
        return new Enrolled(accountId, insertClient(accountId, name, token), token);
    }

    private Client insertClient(String accountId, String name, String token) {
        Client client = new Client(randomId(16), accountId, name, Instant.now(), null);
        jdbc.update("insert into clients (id, account_id, name, token_hash, created) values (?, ?, ?, ?, ?)",
                client.id(), accountId, name, hash(token), Timestamp.from(client.created()));
        return client;
    }

    /** The client a bearer token belongs to; records the use. */
    public Optional<Client> authenticate(String token) {
        Optional<Client> client = jdbc.query("select * from clients where token_hash = ?", CLIENT, (Object) hash(token))
                .stream().findFirst();
        client.ifPresent(c -> jdbc.update("update clients set last_used = ? where id = ?",
                Timestamp.from(Instant.now()), c.id()));
        return client;
    }

    public List<Client> clients(String accountId) {
        return jdbc.query("select * from clients where account_id = ? order by created", CLIENT, accountId);
    }

    public boolean deleteClient(String accountId, String clientId) {
        return jdbc.update("delete from clients where account_id = ? and id = ?", accountId, clientId) > 0;
    }

    static String randomId(int bytes) {
        byte[] random = new byte[bytes];
        RANDOM.nextBytes(random);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(random);
    }

    private static byte[] hash(String token) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * The single-user version kept one passkey user and keys without an owner. On the first start
     * with accounts, all of that becomes one account, and its CLI token file a client of it, so the
     * existing phone and CLI keep working unchanged.
     */
    private void migrateSingleUserData(Path legacyTokenFile) {
        boolean hasAccounts = jdbc.queryForObject("select count(*) from accounts", Integer.class) > 0;
        int users = jdbc.queryForObject("select count(*) from user_entities", Integer.class);
        int orphanKeys = jdbc.queryForObject("select count(*) from ssh_keys where account_id is null", Integer.class);
        if (hasAccounts || users + orphanKeys == 0) {
            return;
        }
        String id = randomId(16);
        jdbc.update("insert into accounts (id, created) values (?, ?)", id, Timestamp.from(Instant.now()));
        // Passkeys find their user by its handle (user_entities.id), so renaming keeps them valid.
        jdbc.update("update user_entities set name = ?", id);
        jdbc.update("update ssh_keys set account_id = ? where account_id is null", id);
        if (legacyTokenFile != null && Files.isRegularFile(legacyTokenFile)) {
            try {
                insertClient(id, "ssha-cli (single-user token)", Files.readString(legacyTokenFile).strip());
            } catch (IOException e) {
                throw new UncheckedIOException("Cannot read " + legacyTokenFile, e);
            }
        }
        log.info("Migrated the single-user data to account {}", id);
    }
}
