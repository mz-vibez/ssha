package com.maykelange.ssha.server.vault;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.stereotype.Repository;

/**
 * The account's vault key, once per passkey. The key itself is made in a browser and never reaches
 * the server: each slot holds it encrypted (AES-GCM) under a key derived from that passkey's PRF
 * output, which only the authenticator can produce. See ssh.js.
 */
@Repository
public class VaultSlots {

    /**
     * @param credentialId the passkey's credential id, base64url
     * @param wrapped      the vault key, encrypted; the credential id is the additional data
     */
    public record Slot(String credentialId, byte[] iv, byte[] wrapped) {
    }

    private static final RowMapper<Slot> ROW = (rs, n) ->
            new Slot(rs.getString("credential_id"), rs.getBytes("iv"), rs.getBytes("wrapped"));

    private final JdbcTemplate jdbc;

    public VaultSlots(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * The PRF input every passkey of the account is asked for. One per account rather than per slot, so
     * a device can tap whichever passkey it has and learn from the answer whether it has a slot.
     */
    public static byte[] salt(String accountId) {
        try {
            return MessageDigest.getInstance("SHA-256")
                    .digest(("ssha vault v1:" + accountId).getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public List<Slot> findAll(String accountId) {
        return jdbc.query("select * from vault_slots where account_id = ? order by created", ROW, accountId);
    }

    public boolean has(String accountId, Bytes credentialId) {
        return jdbc.queryForObject("select count(*) from vault_slots where account_id = ? and credential_id = ?",
                Integer.class, accountId, credentialId.toBase64UrlString()) > 0;
    }

    public boolean exists(String accountId) {
        return jdbc.queryForObject("select count(*) from vault_slots where account_id = ?", Integer.class, accountId) > 0;
    }

    /**
     * @param create true for the account's first slot, which brings the vault key into being; false for
     *               a passkey given the existing key by another device
     * @throws IllegalStateException if {@code create} doesn't match whether the account has a vault, or
     *                               the passkey has a slot already (slots are never replaced)
     */
    public synchronized void add(String accountId, Bytes credentialId, byte[] iv, byte[] wrapped, boolean create) {
        if (exists(accountId) == create) {
            throw new IllegalStateException(create ? "the account has a vault already" : "the account has no vault yet");
        }
        try {
            jdbc.update("insert into vault_slots (account_id, credential_id, iv, wrapped, created) values (?, ?, ?, ?, ?)",
                    accountId, credentialId.toBase64UrlString(), iv, wrapped, Timestamp.from(Instant.now()));
        } catch (DuplicateKeyException e) {
            throw new IllegalStateException("this passkey has the vault key already");
        }
    }

    public void delete(String accountId, Bytes credentialId) {
        jdbc.update("delete from vault_slots where account_id = ? and credential_id = ?",
                accountId, credentialId.toBase64UrlString());
    }
}
