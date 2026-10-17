package com.maykelange.ssha.server.ssh;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

/**
 * The account's SSH keys: public halves, and private halves encrypted in the browser under the
 * account's vault key, which the server never has (see VaultSlots).
 */
@Repository
public class SshKeys {

    private static final RowMapper<SshKey> ROW = (rs, n) -> new SshKey(rs.getString("id"), rs.getString("account_id"),
            rs.getString("label"),
            rs.getBytes("public_key"), rs.getTimestamp("created").toInstant());

    /**
     * A private key as the browser encrypted it (AES-GCM, the public key blob as additional data).
     *
     * @param type "ssh-ed25519" or "ssh-rsa"
     * @param data the PKCS#8 private key, encrypted
     */
    public record Sealed(String id, String type, byte[] publicKey, byte[] iv, byte[] data) {
    }

    /** Large enough for an 8192-bit RSA key's PKCS#8 encoding plus the GCM tag. */
    public static final int MAX_SEALED_LENGTH = 8192;

    private final JdbcTemplate jdbc;

    public SshKeys(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public List<SshKey> findAll(String accountId) {
        return jdbc.query("select * from ssh_keys where account_id = ? order by created", ROW, accountId);
    }

    public Optional<SshKey> findByPublicKey(String accountId, byte[] blob) {
        return jdbc.query("select * from ssh_keys where account_id = ? and id = ?", ROW, accountId, SshWire.keyId(blob))
                .stream().findFirst();
    }

    /**
     * @param blob SSH public key blob; must pass {@link SshWire#checkUserKey}
     * @throws IllegalArgumentException if another account has the key already
     */
    public SshKey add(String accountId, String label, byte[] blob) {
        SshWire.checkUserKey(blob);
        SshKey key = new SshKey(SshWire.keyId(blob), accountId, label, blob, Instant.now());
        try {
            jdbc.update("insert into ssh_keys (id, account_id, label, public_key, created) values (?, ?, ?, ?, ?)",
                    key.id(), accountId, key.label(), key.publicKey(), Timestamp.from(key.created()));
        } catch (DuplicateKeyException e) {
            throw new IllegalArgumentException("this key is already in use by another account");
        }
        return key;
    }

    /** The account's keys whose private half is stored here. */
    public List<Sealed> sealed(String accountId) {
        return jdbc.query("select * from ssh_keys where account_id = ? and key_data is not null order by created",
                (rs, n) -> new Sealed(rs.getString("id"), SshWire.algorithm(rs.getBytes("public_key")),
                        rs.getBytes("public_key"), rs.getBytes("key_iv"), rs.getBytes("key_data")),
                accountId);
    }

    /** Stores the key's encrypted private half, unless it has one already (the first copy stays). */
    public void seal(String accountId, String id, byte[] iv, byte[] data) {
        if (iv == null || iv.length != 12 || data == null || data.length < 16 || data.length > MAX_SEALED_LENGTH) {
            throw new IllegalArgumentException("invalid encrypted key");
        }
        jdbc.update("update ssh_keys set key_iv = ?, key_data = ? where account_id = ? and id = ? and key_data is null",
                iv, data, accountId, id);
    }

    public boolean delete(String accountId, String id) {
        return jdbc.update("delete from ssh_keys where account_id = ? and id = ?", accountId, id) > 0;
    }
}
