package com.maykelange.ssha.server;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

/** Public keys of the phone's SSH keys, by account. Private keys never reach the server. */
@Repository
public class SshKeys {

    private static final RowMapper<SshKey> ROW = (rs, n) -> new SshKey(rs.getString("id"), rs.getString("account_id"),
            rs.getString("label"),
            rs.getBytes("public_key"), rs.getTimestamp("created").toInstant());

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

    public boolean delete(String accountId, String id) {
        return jdbc.update("delete from ssh_keys where account_id = ? and id = ?", accountId, id) > 0;
    }
}
