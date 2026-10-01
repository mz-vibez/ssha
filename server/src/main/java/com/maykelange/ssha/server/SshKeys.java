package com.maykelange.ssha.server;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

/** Public keys of the phone's SSH keys. Private keys never reach the server. */
@Repository
public class SshKeys {

    private static final RowMapper<SshKey> ROW = (rs, n) -> new SshKey(rs.getString("id"), rs.getString("label"),
            rs.getBytes("public_key"), rs.getTimestamp("created").toInstant());

    private final JdbcTemplate jdbc;

    public SshKeys(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public List<SshKey> findAll() {
        return jdbc.query("select * from ssh_keys order by created", ROW);
    }

    public Optional<SshKey> findById(String id) {
        return jdbc.query("select * from ssh_keys where id = ?", ROW, id).stream().findFirst();
    }

    public Optional<SshKey> findByPublicKey(byte[] blob) {
        return findById(SshWire.keyId(blob));
    }

    /** @param blob SSH public key blob; must pass {@link SshWire#checkUserKey} */
    public SshKey add(String label, byte[] blob) {
        SshWire.checkUserKey(blob);
        SshKey key = new SshKey(SshWire.keyId(blob), label, blob, Instant.now());
        jdbc.update("insert into ssh_keys (id, label, public_key, created) values (?, ?, ?, ?)",
                key.id(), key.label(), key.publicKey(), Timestamp.from(key.created()));
        return key;
    }

    public boolean delete(String id) {
        return jdbc.update("delete from ssh_keys where id = ?", id) > 0;
    }
}
