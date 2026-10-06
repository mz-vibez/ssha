# ssha

An SSH agent whose keys live on your phone: every signature is approved, and made, on the phone.

- `server/` — Spring Boot (port 9091). The phone pages are server-rendered Thymeleaf templates;
  sign requests are rendered to HTML on the server and pushed over Server-Sent Events, htmx just
  swaps them into the page.
- `cli/` — plain Java 25 client (no Spring, also builds as a GraalVM native executable): the agent itself, plus account setup, enrolment and
  key listing, talking to the server's `/api` endpoints.

The server hosts any number of accounts. Each has its own passkeys, SSH keys, sign requests and computers.

Public URL: https://ssha.apps.maykelange.com/ (load balancer → this machine:9091)

## Build

Requires JDK 25 (Spring Boot 4.1). `mise.toml` pins Temurin 25 for this directory; the build
fails fast with a clear message on an older JDK.

    mvn package

### Native CLI (GraalVM)

`mise.toml` also installs GraalVM CE 25 (Temurin stays the default JDK). Build a native executable with

    mise run native        # → cli/target/ssha-cli (≈35 MB, starts in milliseconds, no JDK needed)

It needs gcc and the zlib development files (`sudo apt install zlib1g-dev` on Debian/Ubuntu). The CLI
uses only Jackson's streaming API (`Json`), so there is no reflection to configure. Like the jar, the
executable finds the project's `data/` folder from its own location; a copy elsewhere (e.g. downloaded from the
server) keeps its token and agent socket in `~/.config/ssha` (`$XDG_CONFIG_HOME/ssha`).

## Run the server

    java -jar server/target/ssha-server.jar

## Deploy with Docker

No image to build or registry needed: [`deploy/docker-compose.yml`](deploy/docker-compose.yml) runs the jar in the
stock `eclipse-temurin:25-jre` image, with the jar and the data in folders on the host. Caddy terminates HTTPS and
forwards to it ([`deploy/Caddyfile`](deploy/Caddyfile)).

1. On the host, create a folder with subfolders `app` and `data`.
2. Build with `mvn package` and copy `server/target/ssha-server.jar` to `app/`. To offer the CLI for download on the
   Computers page, also build it with `mise run native` and copy `cli/target/ssha-cli` there.
3. Copy `deploy/docker-compose.yml` into the folder and edit the lines marked `EDIT`: the user that owns `data/`,
   the time zone and the domain.
4. `docker compose up -d` in the folder. The server listens on `127.0.0.1:9091` on the host.
5. Add the [`deploy/Caddyfile`](deploy/Caddyfile) site block to Caddy and reload it.

Updating: copy the new jars into `app/` and `docker compose restart`. Schema changes apply themselves
on start.

Moving an existing server: stop it, copy its `data/` folder (`ssha.mv.db`, `vapid`, and `token` if present) into
the new folder's `data/`, make it owned by the user from the compose file, then start the container. Keep the same
domain, or the passkeys stop working.

If the server stops at startup with "The data folder /data is not writable" (or, from older versions, H2's "The
database is read only"), the container's `user:` can't write `data/`: `sudo chown -R <uid>:<gid> data` with the
compose file's `user:` values, or set `user:` to the folder's owner.

Back up `data/`: it holds the accounts, passkeys, computers' token hashes, the public keys and the push key. The
private SSH keys are never there; they only live on the phones.

## Use the CLI

On a computer without a checkout, get the native CLI from the phone's **Computers** page, which links to it and
shows the commands to fetch and run it, e.g. `curl -fLO https://<server>/download/ssha-cli && chmod +x ssha-cli`.
The server offers `ssha-cli` from `ssha.downloads-dir` (`cli/target` of the checkout by default) when it is there.
A downloaded CLI keeps its token in `~/.config/ssha`.

    java -jar cli/target/ssha-cli.jar                 # first run: create an account (see Accounts below)
    java -jar cli/target/ssha-cli.jar --account ID    # first run on another computer: join account ID
    java -jar cli/target/ssha-cli.jar enroll          # QR code + one-time link to add a passkey on the phone
    java -jar cli/target/ssha-cli.jar agent           # ssh-agent backed by the phone (see below)
    java -jar cli/target/ssha-cli.jar keys            # the phone's SSH public keys as authorized_keys lines

The CLI targets the public URL by default; override with `--url http://localhost:9091` or `$SSHA_URL`.

## Accounts

- **New account:** run `ssha-cli` on a computer that has no token yet. The server creates an account with a random
  id (128 bits, e.g. `l5Gn7tgVI4tpy-ufe7RiZA`) and a token for this computer, saved to `data/token` (mode 600).
  The CLI prints the id and a QR code for adding the account's first passkey on the phone.
  Or start on the phone: **Create an account** on the sign-in page creates one, signs the browser in and opens the
  passkeys page to add its passkey; then add computers to it as below.
  Set `ssha.open-registration=false` to stop strangers from creating accounts on your server (both ways).
- **Another computer:** run `ssha-cli --account <id>` (or set `$SSHA_ACCOUNT`) there. The phone's start page shows a
  *New computer* card with its host name, IP address and a code that is also printed in the terminal; **Accept**
  gives that computer its own token. Unanswered requests fail after 2 minutes (`ssha.join-timeout`), and an account
  has at most 5 requests waiting at once.
- **Computers** on the phone lists every computer with access and when it was last used; **Remove** revokes its token.
- The account id is the account's name on the phone (it's what the passkey is registered under). Knowing it only lets
  someone *ask* to join; the phone still has to accept.
- `ssha-cli` with no command on a set-up computer prints its account id. With a token, `--account` just checks
  that the token belongs to that account.

## SSH agent

The phone holds the SSH keys; the computer only gets signatures, and each one needs a tap on the phone.

1. On the phone, open **Keys** and create a key. It is an Ed25519 key generated in the browser and stored
   in the browser's IndexedDB, encrypted (AES-GCM) with a secret derived from your passkey via the WebAuthn
   PRF extension. The server only gets the public key.
   Or **import** an existing Ed25519 or RSA key on the same page: pick or paste an OpenSSH private key
   file (passphrase-protected or not; aes-ctr/aes-gcm, as `ssh-keygen` writes them), an RSA PKCS#1 PEM
   (`BEGIN RSA PRIVATE KEY`) or an unencrypted PKCS#8 PEM key. The file is decrypted and re-encrypted
   under your passkey on the phone; only the public key is sent. Importing the same key in another
   browser adds it there under the existing entry.
   - RSA keys need at least 2048 bits. They sign with rsa-sha2-256 or rsa-sha2-512, whichever ssh asks
     for; legacy SHA-1 `ssh-rsa` signatures are refused (OpenSSH disables them by default too).
   - Old-style passphrase-protected PEM files (`Proc-Type: 4,ENCRYPTED`) can't be read; convert them with
     `ssh-keygen -p -f <file>`, which rewrites them in the OpenSSH format.
   - ECDSA and DSA keys are not supported.
2. Put its line (shown on the page, or `ssha-cli keys`) in `~/.ssh/authorized_keys` on a server, or add it
   to GitHub.
3. Run `ssha-cli agent` and use the socket it prints, e.g. `export SSH_AUTH_SOCK=<project>/data/agent.sock`
   (or `IdentityAgent` in `~/.ssh/config`).
4. When ssh needs a signature, the start page shows a card: key, remote user, host key fingerprint (marked
   *verified* when OpenSSH's session binding proves it), and the machine asking. **Approve** unlocks the key
   with your passkey, signs on the phone and sends only the signature back; **Deny** makes ssh fail.
   Unanswered requests fail after 60 s (`ssha.sign-timeout`). `ssh-keygen -Y sign` (git commit signing)
   works the same way and shows as a *Signature* with its namespace.

Things to know:

- Needs a passkey provider with PRF (iCloud Keychain on iOS 18+, Google Password Manager on Android) and a
  browser with WebCrypto Ed25519. Passkeys registered before this feature may need re-adding.
- The key exists only in that browser's storage. Clearing site data, or iOS evicting it (Safari can drop
  storage of sites unused for 7 days; adding the page to the home screen avoids that), loses the key — keep
  a second key or another way in for anything important.
- **Notifications:** tap *Turn on notifications* on the start page to be notified of every sign and join request,
  even with the page closed (see *Phone app* below). Answering still happens on the start page.
- The phone runs JavaScript served by this server, so whoever controls the server could serve code that
  copies a key while it's unlocked. Fine for a self-hosted server; a hardware key is stronger.

## Phone app

The phone pages are a PWA: install it with *Add to Home Screen* (iOS: Share menu; Android Chrome: menu → *Install
app*). It opens full screen, from its own icon.

- **Push notifications** use standard Web Push (VAPID, `aes128gcm`), implemented with the JDK's own crypto in
  `WebPush`. The server's key pair is generated into `data/vapid` on first start; deleting it invalidates every
  subscription (browsers then offer to turn notifications on again). `ssha.vapid-subject` is the contact URL the push
  services see. The server only sends to Google, Mozilla, Apple and Microsoft push services (`ssha.push-hosts`).
- A notification holds only what the request card shows (kind, key, user, computer, join code). It is end-to-end
  encrypted to the browser; the push service can't read it.
- **iPhone:** Web Push only works in the Home Screen app (iOS 16.4+), so the button shows there and not in Safari.
  The Home Screen app has its **own storage, separate from Safari's**: create or import SSH keys from inside the app,
  since keys stored in Safari aren't visible to it. Passkeys are shared. Being on the Home Screen also stops iOS
  from evicting the keys after 7 days of not using Safari for the site.
- Signing out turns notifications off for that browser. A computer's or browser's subscription follows whichever
  account last signed in there.

## Authentication

- **Phone:** passkeys only (Spring Security WebAuthn); each account is a user named by its id. Sessions last
  30 days of inactivity but live in memory, so a server restart means one passkey tap.
- **First passkey / new device / recovery:** run `ssha-cli enroll`, scan the QR code, press
  *Continue*, then *Add* on the passkeys page. Links are single use and expire after 10 minutes.
- **CLI:** a bearer token per computer, from `$SSHA_TOKEN` or `data/token` (`~/.config/ssha/token` outside a
  checkout). The server stores only SHA-256
  hashes of tokens. To rotate one: remove the computer on the phone, delete `data/token` and join again.
- **Upgrading from the single-user version:** on the first start, the existing passkeys and SSH keys become one
  account, and the old server-generated `data/token` becomes one of its computers, so nothing needs redoing.
  Run `ssha-cli` to see the new account id.
- Accounts, tokens, passkeys and public keys are stored in an H2 database in `data/`.
- Run from a checkout, nothing is stored outside the project folder: both jars locate it from their own
  location, so they can be started from any directory. `data/` is git-ignored — it holds secrets.
- Passkeys are bound to `ssha.rp-id` (`ssha.apps.maykelange.com`); changing the domain invalidates them.

## Endpoints

| Method | Path            | Used by | Notes                                                        |
|--------|-----------------|---------|--------------------------------------------------------------|
| GET    | `/login`        | phone   | Passkey sign-in page                                          |
| GET    | `/login/ott`    | phone   | Landing page for the `enroll` link                            |
| GET    | `/passkeys`     | phone   | List / add / delete passkeys                                  |
| GET    | `/`             | phone   | Start page: sign requests waiting for approval                |
| GET    | `/stream`       | phone   | SSE of rendered sign request cards; pending ones on connect   |
| POST   | `/signup`       | phone   | Create an account and sign in to it; → `/passkeys?new`         |
| GET    | `/download/ssha-cli` | anyone | The native CLI, if built                                  |
| POST   | `/push/subscribe` | phone | `PushSubscription.toJSON()`; 204                             |
| POST   | `/push/unsubscribe` | phone | `{endpoint}`; 204                                            |
| GET    | `/clients`      | phone   | Computers with access to the account; remove them             |
| POST   | `/join/{id}/accept` | phone | Accept a computer's join request; 204                        |
| POST   | `/join/{id}/deny` | phone | 204                                                           |
| POST   | `/api/accounts` | CLI (no token) | `{client}` → new account `{account, token}`            |
| POST   | `/api/accounts/{id}/clients` | CLI (no token) | `{client, code}`; waits for the phone: 200 `{account, token}`, 403, 404, 408, 429 |
| GET    | `/api/account`  | CLI     | `{account}` the token belongs to                              |
| POST   | `/api/enroll`   | CLI     | Returns a one-time sign-in link `{url, expiresAt}`            |
| GET    | `/keys`         | phone   | List / create / delete SSH keys                               |
| POST   | `/sign/{id}/approve` | phone | Form field `signature` (raw signature, base64url); 204     |
| POST   | `/sign/{id}/deny` | phone | 204                                                           |
| GET    | `/api/keys`     | CLI     | Public keys for the agent                                     |
| POST   | `/api/sign`     | CLI     | Waits for the phone: 200 `{signature}`, 403 denied, 408 timeout |

All other `/api` endpoints need `Authorization: Bearer <token>` and act on that token's account; everything else
needs a signed-in session and acts on its account.

Pending sign and join requests are kept in memory; a server restart fails them (ssh just reports an agent error).

## License

Copyright (C) 2026 Maykel AL ZREIBI

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero
General Public License as published by the Free Software Foundation, either version 3 of the License, or (at
your option) any later version. It is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See
[LICENSE](LICENSE) for the full text.

Because the server is meant to be used over a network, the AGPL requires that if you run a modified version
for others, you offer them its source code.
