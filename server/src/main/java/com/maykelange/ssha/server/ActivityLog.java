package com.maykelange.ssha.server;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import jakarta.servlet.http.HttpServletRequest;

/**
 * An account's history: how each sign request ended, and how its browsers signed in and out. Only the
 * newest {@link #KEEP} rows per account are kept.
 */
@Repository
public class ActivityLog {

    static final int KEEP = 1000;
    static final String SIGN = "sign";
    static final String WEB = "web";

    /** @param source the computer (sign) or the browser's address and user agent (web) */
    public record Entry(Instant at, String category, String event, String detail, String source) {
    }

    private final JdbcTemplate jdbc;

    public ActivityLog(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public void record(String accountId, String category, String event, String detail, String source) {
        jdbc.update("insert into activity (account_id, at, category, event, detail, source) values (?, ?, ?, ?, ?, ?)",
                accountId, Timestamp.from(Instant.now()), category, event, cut(detail, 500), cut(source, 300));
        jdbc.update("delete from activity where account_id = ? and id not in "
                + "(select id from activity where account_id = ? order by id desc limit ?)", accountId, accountId, KEEP);
    }

    /** Records a browser event with the address and user agent of {@code request}. */
    public void web(String accountId, String event, String detail, HttpServletRequest request) {
        record(accountId, WEB, event, detail, describe(request));
    }

    /** The newest entries of a category, newest first. */
    public List<Entry> recent(String accountId, String category, int limit) {
        return jdbc.query("select at, category, event, detail, source from activity "
                        + "where account_id = ? and category = ? order by id desc limit ?",
                (rs, n) -> new Entry(rs.getTimestamp("at").toInstant(), rs.getString("category"),
                        rs.getString("event"), rs.getString("detail"), rs.getString("source")),
                accountId, category, limit);
    }

    static String describe(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        String agent = request.getHeader("User-Agent");
        String address = request.getRemoteAddr();
        return agent == null ? address : address + " · " + agent.replaceAll("\\p{Cntrl}", " ");
    }

    private static String cut(String s, int max) {
        return s == null || s.length() <= max ? s : s.substring(0, max - 1) + "…";
    }
}
