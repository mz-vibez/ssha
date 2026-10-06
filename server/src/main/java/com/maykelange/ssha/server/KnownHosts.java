package com.maykelange.ssha.server;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

/**
 * The hosts an account has logged in to, by host key fingerprint. Only host keys proven by OpenSSH's
 * session binding are recorded, so a fingerprint can't be planted by whoever sends the sign request.
 */
@Repository
public class KnownHosts {

    /** @param logins approved logins so far */
    public record Seen(Instant firstSeen, int logins) {
    }

    private final JdbcTemplate jdbc;

    public KnownHosts(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Optional<Seen> find(String accountId, String fingerprint) {
        return jdbc.query("select first_seen, logins from known_hosts where account_id = ? and fingerprint = ?",
                (rs, n) -> new Seen(rs.getTimestamp("first_seen").toInstant(), rs.getInt("logins")),
                accountId, fingerprint).stream().findFirst();
    }

    /** Records an approved login to the host. */
    public void login(String accountId, String fingerprint) {
        Timestamp now = Timestamp.from(Instant.now());
        if (jdbc.update("update known_hosts set last_seen = ?, logins = logins + 1 where account_id = ? and fingerprint = ?",
                now, accountId, fingerprint) == 0) {
            jdbc.update("merge into known_hosts (account_id, fingerprint, first_seen, last_seen, logins) "
                    + "key (account_id, fingerprint) values (?, ?, ?, ?, 1)", accountId, fingerprint, now, now);
        }
    }
}
