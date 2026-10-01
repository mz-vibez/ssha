# ssha

An SSH agent whose keys live on your phone: every signature is approved, and made, on the phone.

- `server/` — Spring Boot (port 9091). The phone pages are server-rendered Thymeleaf templates;
  sign requests are rendered to HTML on the server and pushed over Server-Sent Events, htmx just
  swaps them into the page.
- `cli/` — plain Java 25 client (no Spring, also builds as a GraalVM native executable): the agent itself, plus enrolment and key listing, talking
  to the server's `/api` endpoints.

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
executable finds the project's `data/` folder from its own location; a copy elsewhere needs
`$SSHA_TOKEN`, and its agent socket goes to `./data/agent.sock`.

## Run the server

    java -jar server/target/ssha-server.jar

## Use the CLI

    java -jar cli/target/ssha-cli.jar enroll          # QR code + one-time link to add a passkey on the phone
    java -jar cli/target/ssha-cli.jar agent           # ssh-agent backed by the phone (see below)
    java -jar cli/target/ssha-cli.jar keys            # the phone's SSH public keys as authorized_keys lines

The CLI targets the public URL by default; override with `--url http://localhost:9091` or `$SSHA_URL`.

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
- The start page has to be open on the phone to see requests (no push notifications yet).
- The phone runs JavaScript served by this server, so whoever controls the server could serve code that
  copies a key while it's unlocked. Fine for a self-hosted server; a hardware key is stronger.

## Authentication

- **Phone:** passkeys only (Spring Security WebAuthn), one account (`ssha.username`). Sessions last
  30 days of inactivity but live in memory, so a server restart means one passkey tap.
- **First passkey / new device / recovery:** run `ssha-cli enroll`, scan the QR code, press
  *Continue*, then *Add* on the passkeys page. Links are single use and expire after 10 minutes.
- **CLI:** bearer token. The server generates `data/token` (mode 600) on first start; the CLI reads
  it from there. On another machine, set `$SSHA_TOKEN`. To rotate: delete the file and restart the server.
- Passkeys are stored in an H2 database in `data/`.
- Nothing is stored outside the project folder. Both jars locate the project folder from their own
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
| POST   | `/api/enroll`   | CLI     | Returns a one-time sign-in link `{url, expiresAt}`            |
| GET    | `/keys`         | phone   | List / create / delete SSH keys                               |
| POST   | `/sign/{id}/approve` | phone | Form field `signature` (raw signature, base64url); 204     |
| POST   | `/sign/{id}/deny` | phone | 204                                                           |
| GET    | `/api/keys`     | CLI     | Public keys for the agent                                     |
| POST   | `/api/sign`     | CLI     | Waits for the phone: 200 `{signature}`, 403 denied, 408 timeout |

All `/api` endpoints need `Authorization: Bearer <token>`; everything else needs a signed-in session.

Pending sign requests are kept in memory; a server restart fails them (ssh just reports an agent error).

## License

Copyright (C) 2026 Maykel AL ZREIBI

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero
General Public License as published by the Free Software Foundation, either version 3 of the License, or (at
your option) any later version. It is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See
[LICENSE](LICENSE) for the full text.

Because the server is meant to be used over a network, the AGPL requires that if you run a modified version
for others, you offer them its source code.
