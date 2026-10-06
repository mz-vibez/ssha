# Security review: open issues

State of the code as of commit `082cfbb` (Harden the agent against stolen tokens, prompt fatigue and a
lying server). The review read every source file of `server/` and `cli/`, the templates, the browser
scripts and the deployment files. Items are ordered by severity within each section; each names the
code it concerns and a fix. Resolved items are listed at the end so the history of the review stays
with the code.

## Open

### Medium

1. **Rate limits and the join card's IP address trust the proxy's forwarded headers.**
   `server.forward-headers-strategy=framework` makes `getRemoteAddr()` return the first
   `X-Forwarded-For` value, so every per-address limit (`RateLimits`) and the address shown on a join
   card (`JoinService`) come from that header. Caddy strips client-supplied forwarding headers by
   default, so the documented deployment is fine, but anyone who can reach port 9091 directly, or sit
   behind a load balancer that passes the header through, gets a fresh limit bucket per request by
   rotating the header, and can print any address on the join card.
   *Fix:* document that the proxy must overwrite `X-Forwarded-For` and that nothing but the proxy may
   reach the port; consider refusing requests whose `X-Forwarded-For` has more than one hop, or
   switching to the `native` strategy with Tomcat's `RemoteIpValve` and an internal-proxies list.

2. **The phone's key-mismatch check accepts any warning, not the key warning.**
   `ssh.js` (`checkCard`) tolerates a login that names a different key than the one signing whenever
   `data-warning` is `true`. `SignDetails.login` replaces the key-mismatch warning with the host-mismatch
   one when the session binding fails, so a card can show only the host warning while the key also
   disagrees, and the phone still signs.
   *Fix:* render a dedicated flag (e.g. `data-key-mismatch`) and have the phone check that one; keep
   both warnings on the card when both apply.

3. **No way to see or end sessions.**
   Phone sessions last 30 days of inactivity. Deleting a passkey does not end the sessions it created,
   and nothing lists them. A session gained by mistake (an enrol request accepted in error) outlives
   the clean-up.
   *Fix:* a "sign out everywhere" action, or end every session of the account when a passkey is
   deleted; a session registry (Spring Session or `SessionRegistry`) makes both possible.

### Low

4. **The phone cannot verify the host for logins that are not hostbound.**
   For servers older than OpenSSH 8.9 the host fingerprint on the card comes from the session binding,
   which the phone never sees, so the *verified* label is the server's word. The phone already checks
   the hostbound case itself.
   *Fix:* send the binding (host key, session id, signature) to the phone and verify the host's
   signature in WebCrypto (Ed25519, ECDSA P-256/384/521 and RSA are available).

5. **Only the later request is flagged as concurrent.**
   `SignService.request` sets `concurrent` on a request that arrives while others wait. If a stranger's
   request lands first, the user's own request gets the warning and the stranger's does not.
   *Fix:* re-render every waiting card when a new one arrives so each carries the flag.

6. **A computer can hold the single enrol slot.**
   `EnrollService` allows one pending request per account, each lasting `ssha.join-timeout`, five per
   ten minutes. A stolen token can keep the legitimate `ssha-cli enroll` returning 429 for most of a
   ten-minute window. The user can deny it on the phone, which frees the slot.
   *Fix:* allow a small number of pending requests per account, or let the phone's denial also
   suspend further enrol requests from that computer for a while.

7. **The public one-time-token generation endpoint still generates.**
   `POST /ott/generate` answers 404 (`SecurityConfig`), but Spring's `GenerateOneTimeTokenFilter` runs
   before authorization and calls `OneTimeTokenService.generate` first, so an anonymous caller with a
   CSRF token can add entries to the in-memory service, which only prunes expired entries once it holds
   a hundred.
   *Fix:* give the login filter a wrapper `OneTimeTokenService` whose `generate` throws and whose
   `consume` delegates; keep the real service for `/api/enroll`.

8. **The agent socket is briefly accessible to other users.**
   `SshAgent.serve` binds the Unix socket and then sets its permissions to 600; between the two the
   socket has the process's umask permissions.
   *Fix:* bind inside a directory created with mode 700 (the config directory already is), or set the
   umask before binding.

9. **The CLI defaults to the author's server.**
   `SshaCli.DEFAULT_URL` is the public instance. A self-hoster's user who downloads the binary from
   their own server and runs the command shown on the Computers page, which omits `--url`, talks to the
   author's server instead. Nothing leaks, but accounts end up in the wrong place.
   *Fix:* print `--url <server>` in the Computers page commands, or have the server write its URL into
   the binary it serves.

10. **Open registration defaults to on.**
    `ssha.open-registration=true` lets anyone create accounts on a freshly deployed server; the per-
    address limit bounds the rate but not the total, and accounts that never gain a passkey or a
    computer are never removed.
    *Fix:* default to `false` and expire accounts without a passkey or client after a day.

11. **Container hardening.**
    `deploy/docker-compose.yml` pins the image by tag rather than digest and does not set
    `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]` or `read_only: true` with a tmpfs for
    `/tmp`.

12. **Requester-chosen text reaches the lock screen.**
    Join and enrol notifications carry the requester's name and code. Rate limits now bound this to
    ten join requests per account per ten minutes, so it is an accepted residual; a generic body for
    join notifications would remove it entirely.

## Resolved in `082cfbb`

- htmx loaded from unpkg.com without integrity check, no Content-Security-Policy → served from the
  jar (webjars), strict CSP on every page, htmx eval and script tags disabled.
- A computer's token minted a full web sign-in link → once the account has a passkey the phone must
  accept an enrol request first; no recovery without a passkey, documented.
- The "From" line on sign cards was the request's own claim → taken from the stored client record
  (`ClientPrincipal`).
- No limit on pending sign requests → 2 per computer and 5 per account waiting, 20 per computer per
  minute.
- No rate limits on account creation and join requests → per address and per account.
- The phone signed whatever the card described → it decodes the payload itself and refuses on
  mismatch; verified hosts are remembered and first logins marked.
- The agent kept only the last session binding → keeps the chain, refuses rebinding a connection
  bound for authentication, reports forwarded on any hop.
