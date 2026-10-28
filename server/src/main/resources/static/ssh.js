// The phone half of the SSH agent. Private keys never leave the browser unencrypted, so this part runs
// here. The account has one vault key, made in a browser and never seen by the server, which keeps it
// encrypted once per passkey (AES-GCM under a key derived from that passkey's PRF output), and keeps
// each SSH private key (PKCS#8) encrypted under the vault key. Every use takes a passkey tap.
// A passkey without a copy of the vault key gets one from a device that has it: this device sends an
// ECDH public key, the other one encrypts the vault key to it, and both show a code derived from that
// public key for the user to compare. A passkey synced between devices needs nothing of the sort.
// Keys made before the vault are kept in this browser's IndexedDB, encrypted under a passkey directly;
// they still work, and "Sync" moves them into the vault.
(function () {
    const b64url = {
        encode(buffer) {
            return btoa(String.fromCharCode(...new Uint8Array(buffer)))
                .replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
        },
        decode(value) {
            const bin = atob(value.replace(/-/g, "+").replace(/_/g, "/"));
            return Uint8Array.from(bin, (c) => c.charCodeAt(0));
        },
    };

    function csrfHeaders() {
        const token = document.querySelector("meta[name=_csrf]").content;
        const header = document.querySelector("meta[name=_csrf_header]").content;
        return { [header]: token };
    }

    const postJson = (url, body) => fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json", "HX-Request": "true", ...csrfHeaders() },
        body: JSON.stringify(body),
    });

    /** The server's reason for a 400 or 409, else the status. */
    async function failure(response) {
        const reason = [400, 409].includes(response.status) ? await response.text() : "";
        return new Error(reason || `server answered HTTP ${response.status}`);
    }

    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

    // --- IndexedDB -------------------------------------------------------------------------------
    // keys: keys from before the vault, { id, label, type, publicKey, credentialId, salt, iv, ciphertext,
    //   created }. type is "ssh-ed25519" or "ssh-rsa"; publicKey is the SSH public key blob (records from
    //   before RSA support have no type and hold the raw Ed25519 key). Either way it is the AES-GCM
    //   additional data.
    // join: this device's request for the vault key while it waits for the answer, { id: "current",
    //   request, code, credentialId, publicKey, privateKey, slotKey }; the keys are non-extractable.

    function store(name, mode, action) {
        return new Promise((resolve, reject) => {
            const open = indexedDB.open("ssha", 2);
            open.onupgradeneeded = () => {
                for (const s of ["keys", "join"]) {
                    if (!open.result.objectStoreNames.contains(s)) open.result.createObjectStore(s, { keyPath: "id" });
                }
            };
            open.onerror = () => reject(open.error);
            open.onsuccess = () => {
                const tx = open.result.transaction(name, mode);
                const request = action(tx.objectStore(name));
                tx.oncomplete = () => { open.result.close(); resolve(request.result); };
                tx.onerror = () => { open.result.close(); reject(tx.error); };
            };
        });
    }
    const allLegacyKeys = () => store("keys", "readonly", (s) => s.getAll());
    const deleteLegacyKey = (id) => store("keys", "readwrite", (s) => s.delete(id));
    const getJoin = () => store("join", "readonly", (s) => s.get("current"));
    const putJoin = (record) => store("join", "readwrite", (s) => s.put({ ...record, id: "current" }));
    const clearJoin = () => store("join", "readwrite", (s) => s.delete("current"));

    // --- the vault, as the server keeps it ---------------------------------------------------------

    let vault = { salt: null, slots: [], keys: new Map() };
    let legacy = new Map();

    async function loadVault() {
        const response = await fetch("/vault", { headers: { "HX-Request": "true" } });
        if (response.status === 401) location.href = "/login";
        if (!response.ok) throw await failure(response);
        const v = await response.json();
        vault = {
            salt: b64url.decode(v.salt),
            slots: v.slots.map((s) => ({ ...s, iv: b64url.decode(s.iv), wrapped: b64url.decode(s.wrapped) })),
            keys: new Map(v.keys.map((k) => [k.id, {
                ...k, publicKey: b64url.decode(k.publicKey), iv: b64url.decode(k.iv), data: b64url.decode(k.data),
            }])),
        };
    }

    // Loaded up front: Safari only allows a passkey prompt straight from a tap, so the approve handler
    // must reach navigator.credentials.get() without waiting on the network or IndexedDB first.
    const reload = () => Promise.all([
        allLegacyKeys().then((records) => { legacy = new Map(records.map((r) => [r.id, r])); }),
        loadVault(),
    ]);
    const loaded = reload();

    const slotIds = () => vault.slots.map((s) => s.credentialId);

    // The passkey this browser last opened the vault with: whether it can is only certain after a tap.
    const REMEMBERED = "ssha.vault-passkey";
    function remember(credentialId) {
        try { localStorage.setItem(REMEMBERED, credentialId); } catch (e) { /* only a hint */ }
    }
    function canOpenHere() {
        try { return slotIds().includes(localStorage.getItem(REMEMBERED)); } catch (e) { return false; }
    }

    // --- crypto ----------------------------------------------------------------------------------

    /**
     * One passkey tap, with its PRF evaluated at `first` (and `second`). `allow` lists the credential ids
     * the browser may offer; empty for any passkey of this site.
     */
    async function tap({ allow = [], first, second }) {
        // Plain ArrayBuffer copies: passkey-provider extensions (KeePassXC) intercept this call, and the
        // PRF inputs they forward must convert to an ArrayBuffer there, which a view onto a shared one may not.
        const bytes = (view) => {
            const u8 = view instanceof ArrayBuffer ? new Uint8Array(view) : new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
            return u8.slice().buffer;
        };
        let cred;
        try {
            cred = await navigator.credentials.get({
                publicKey: {
                    challenge: bytes(crypto.getRandomValues(new Uint8Array(32))),
                    userVerification: "required",
                    allowCredentials: allow.map((id) => ({
                        type: "public-key", id: bytes(typeof id === "string" ? b64url.decode(id) : id),
                    })),
                    extensions: { prf: { eval: second ? { first: bytes(first), second: bytes(second) } : { first: bytes(first) } } },
                },
            });
        } catch (e) {
            if (e instanceof TypeError) {
                throw new Error("this passkey provider doesn't support the PRF extension needed to protect SSH keys (" + e.message + ")");
            }
            throw e;
        }
        const results = cred.getClientExtensionResults().prf?.results;
        if (!results?.first || (second && !results.second)) {
            throw new Error("this passkey can't protect SSH keys (its provider doesn't support the PRF extension)");
        }
        const credentialId = new Uint8Array(cred.rawId);
        return { credentialId, id: b64url.encode(credentialId), first: results.first, second: results.second };
    }

    /** A tap with a passkey that holds the vault key (any passkey while the account has no vault). */
    const vaultTap = () => tap({ allow: slotIds(), first: vault.salt });

    async function hkdfKey(secret, salt, info) {
        const material = await crypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveKey"]);
        return crypto.subtle.deriveKey(
            { name: "HKDF", hash: "SHA-256", salt, info: new TextEncoder().encode(info) },
            material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    }
    /** What a passkey's PRF output encrypts its copy of the vault key with. */
    const slotKey = (secret) => hkdfKey(secret, vault.salt, "ssha vault slot v1");
    /** What encrypts the vault key on its way to another device, from the ECDH secret. */
    const grantKey = (bits) => hkdfKey(bits, new Uint8Array(0), "ssha vault grant v1");
    /** What encrypted keys from before the vault. */
    const legacyKey = (secret, salt) => hkdfKey(secret, salt, "ssha ssh key v1");
    const aesKey = (raw) => crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);

    async function seal(key, plaintext, additionalData) {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const data = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData }, key, plaintext));
        return { iv, data };
    }
    async function unseal(key, iv, data, additionalData) {
        return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData }, key, data));
    }

    /**
     * The vault key's raw bytes (the caller zeroes them), opened with the tapped passkey's slot. With
     * `create`, the account's first tap makes the vault key.
     */
    async function vaultKey(t, { create = false } = {}) {
        const slot = vault.slots.find((s) => s.credentialId === t.id);
        if (slot) {
            const raw = await unseal(await slotKey(t.first), slot.iv, slot.wrapped, t.credentialId);
            remember(t.id);
            return raw;
        }
        if (vault.slots.length || !create) {
            throw new Error("this device can't use the synced SSH keys yet: get them on the Keys page");
        }
        const raw = crypto.getRandomValues(new Uint8Array(32));
        const { iv, data } = await seal(await slotKey(t.first), raw, t.credentialId);
        await addSlot(t.id, iv, data, true);
        remember(t.id);
        return raw;
    }

    async function addSlot(credentialId, iv, wrapped, create) {
        const response = await postJson("/vault/slots",
            { credentialId, iv: b64url.encode(iv), wrapped: b64url.encode(wrapped), create });
        if (!response.ok) {
            const error = await failure(response);
            await loadVault().catch(() => {});
            throw error;
        }
        vault.slots.push({ credentialId, iv, wrapped });
    }

    function sshString(bytes) {
        if (typeof bytes === "string") bytes = new TextEncoder().encode(bytes);
        const out = new Uint8Array(4 + bytes.length);
        new DataView(out.buffer).setUint32(0, bytes.length);
        out.set(bytes, 4);
        return out;
    }

    async function createKey(label) {
        const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
        const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
        const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
        const ssh = sshString("ssh-ed25519");
        const blob = new Uint8Array(ssh.length + 4 + raw.length);
        blob.set(ssh);
        blob.set(sshString(raw), ssh.length);
        await storeKey(label, pkcs8, blob);
    }

    async function importKey(text, passphrase, label) {
        const { pkcs8, publicKey, comment } = await window.sshaKeyImport.read(text, passphrase);
        await storeKey((label || comment.trim() || "imported").slice(0, 100), pkcs8, publicKey);
    }

    /** Encrypts `pkcs8` under the vault key (one tap) and stores it with its public key on the server. */
    async function storeKey(label, pkcs8, publicKey) {
        try {
            const raw = await vaultKey(await vaultTap(), { create: true });
            try {
                const { iv, data } = await seal(await aesKey(raw), pkcs8, publicKey);
                await uploadKey(label, publicKey, iv, data);
            } finally {
                raw.fill(0);
            }
        } finally {
            pkcs8.fill(0);
        }
    }

    async function uploadKey(label, publicKey, iv, data) {
        const response = await postJson("/keys",
            { label, publicKey: b64url.encode(publicKey), iv: b64url.encode(iv), data: b64url.encode(data) });
        if (!response.ok) throw await failure(response);
    }

    /** Moves a key from this browser's storage into the vault: one tap opens both. */
    async function syncKey(record) {
        const t = await tap({ allow: [record.credentialId], first: vault.salt, second: record.salt });
        const pkcs8 = await unseal(await legacyKey(t.second, record.salt), record.iv, record.ciphertext, record.publicKey);
        try {
            const raw = await vaultKey(t, { create: true });
            try {
                const { iv, data } = await seal(await aesKey(raw), pkcs8, publicBlob(record));
                await uploadKey(record.label, publicBlob(record), iv, data);
            } finally {
                raw.fill(0);
            }
        } finally {
            pkcs8.fill(0);
        }
        await deleteLegacyKey(record.id);
    }

    /**
     * @param record  a vault key, or one kept in this browser only
     * @param hash    "SHA-256" or "SHA-512" for RSA keys, as the server says ssh asked for
     * @param checked settles once the request is checked; the key is only decrypted if it fulfils
     */
    async function sign(record, data, hash, checked) {
        const algorithm = record.type === "ssh-rsa" ? { name: "RSASSA-PKCS1-v1_5", hash } : { name: "Ed25519" };
        if (record.type === "ssh-rsa" && !hash) throw new Error("the request doesn't say which RSA hash to use");
        let pkcs8;
        if (record.data) {
            const t = await vaultTap();
            await checked;
            const raw = await vaultKey(t);
            try {
                pkcs8 = await unseal(await aesKey(raw), record.iv, record.data, record.publicKey);
            } finally {
                raw.fill(0);
            }
        } else {
            const t = await tap({ allow: [record.credentialId], first: record.salt });
            await checked;
            pkcs8 = await unseal(await legacyKey(t.first, record.salt), record.iv, record.ciphertext, record.publicKey);
        }
        const key = await crypto.subtle.importKey("pkcs8", pkcs8, algorithm, false, ["sign"]);
        pkcs8.fill(0);
        return crypto.subtle.sign(algorithm, key, data);
    }

    // --- devices: handing the vault key over -------------------------------------------------------

    const ECDH = { name: "ECDH", namedCurve: "P-256" };

    /** Six digits from the SHA-256 of a device's public key, as the server computes them: "123 456". */
    async function deviceCode(publicKey) {
        const hash = new DataView(await crypto.subtle.digest("SHA-256", publicKey));
        const digits = String(hash.getUint32(0) % 1000000).padStart(6, "0");
        return `${digits.slice(0, 3)} ${digits.slice(3)}`;
    }

    /**
     * Gets this device the vault key. One tap tells which passkey it has: if that passkey has a slot
     * (synced from another device) that is all; otherwise this asks the account's other devices and
     * returns the request, whose code the user compares with theirs.
     */
    async function askForKeys() {
        const t = await tap({ first: vault.salt });
        if (vault.slots.some((s) => s.credentialId === t.id)) {
            (await vaultKey(t)).fill(0);
            return null;
        }
        const pair = await crypto.subtle.generateKey(ECDH, false, ["deriveBits"]);
        const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
        const response = await postJson("/vault/devices", { credentialId: t.id, publicKey: b64url.encode(publicKey) });
        if (!response.ok) throw await failure(response);
        const { id } = await response.json();
        // The PRF output's key is kept (non-extractable) so the answer can be stored without another tap.
        const request = {
            request: id, code: await deviceCode(publicKey), credentialId: t.credentialId, publicKey,
            privateKey: pair.privateKey, slotKey: await slotKey(t.first),
        };
        await putJoin(request);
        return request;
    }

    /** Waits for another device's answer, then stores this passkey's copy of the vault key. */
    async function receiveKeys(request) {
        let response;
        for (;;) {
            try {
                response = await fetch(`/vault/devices/${request.request}`, { headers: { "HX-Request": "true" } });
                if (![202, 502, 503, 504].includes(response.status)) break;
            } catch (e) {
                // offline for a moment: keep asking
            }
            await sleep(2000);
        }
        if (!response.ok) {
            await clearJoin();
            throw new Error({ 403: "denied on the other device", 408: "not approved in time" }[response.status]
                ?? "the request is gone; ask again");
        }
        const grant = await response.json();
        const theirs = await crypto.subtle.importKey("raw", b64url.decode(grant.ephemeralKey), ECDH, false, []);
        const bits = await crypto.subtle.deriveBits({ name: "ECDH", public: theirs }, request.privateKey, 256);
        const raw = await unseal(await grantKey(bits), b64url.decode(grant.iv), b64url.decode(grant.data), request.publicKey);
        const credentialId = b64url.encode(request.credentialId);
        try {
            const { iv, data } = await seal(request.slotKey, raw, request.credentialId);
            await addSlot(credentialId, iv, data, false);
        } catch (e) {
            // Stored already, by an earlier try whose answer got lost?
            if (!slotIds().includes(credentialId)) throw e;
        } finally {
            raw.fill(0);
        }
        await clearJoin();
        remember(credentialId);
    }

    /** Approves a device's request (on the start page): encrypts the vault key to its public key. */
    async function giveKeys(card) {
        const requester = b64url.decode(card.dataset.publicKey);
        const t = await vaultTap();
        // The card is rendered by the server: the code must be the one of the key the vault key goes to.
        if (await deviceCode(requester) !== card.dataset.code) {
            throw new Error("the code shown doesn't belong to the device's key; not approved");
        }
        const theirs = await crypto.subtle.importKey("raw", requester, ECDH, false, []);
        const ephemeral = await crypto.subtle.generateKey(ECDH, false, ["deriveBits"]);
        const bits = await crypto.subtle.deriveBits({ name: "ECDH", public: theirs }, ephemeral.privateKey, 256);
        const raw = await vaultKey(t);
        let sealed;
        try {
            sealed = await seal(await grantKey(bits), raw, requester);
        } finally {
            raw.fill(0);
        }
        const response = await postJson(`/vault/devices/${card.dataset.vaultRequest}/approve`, {
            ephemeralKey: b64url.encode(await crypto.subtle.exportKey("raw", ephemeral.publicKey)),
            iv: b64url.encode(sealed.iv),
            data: b64url.encode(sealed.data),
        });
        if (response.status === 404) throw new Error("this request was already answered or has expired");
        if (!response.ok) throw await failure(response);
        card.remove();
    }

    // --- what is being signed --------------------------------------------------------------------

    /**
     * What the payload is, decoded here rather than taken from the server: the same cases as the
     * server's SignDetails. Returns { kind, user?, userKey?, hostKey?, namespace? }.
     */
    function describe(data) {
        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        let pos = 0;
        const need = (n) => { if (n < 0 || pos + n > data.length) throw new Error("truncated"); };
        const byte = () => { need(1); return data[pos++]; };
        const string = () => {
            need(4);
            const n = view.getUint32(pos);
            pos += 4;
            need(n);
            const s = data.subarray(pos, pos + n);
            pos += n;
            return s;
        };
        const utf8 = () => new TextDecoder("utf-8", { fatal: true }).decode(string());
        const magic = new TextEncoder().encode("SSHSIG");
        if (data.length > magic.length && magic.every((b, i) => data[i] === b)) {
            try {
                pos = magic.length;
                const namespace = utf8();
                string(); // reserved
                utf8(); // hash algorithm
                string(); // message hash
                if (pos === data.length) return { kind: "Signature", namespace };
            } catch (e) {
                // fall through
            }
        }
        try {
            pos = 0;
            string(); // session id
            if (byte() === 50) { // SSH_MSG_USERAUTH_REQUEST
                const user = utf8();
                utf8(); // service
                const method = utf8();
                const hostbound = method === "publickey-hostbound-v00@openssh.com";
                if ((hostbound || method === "publickey") && byte() !== 0) {
                    utf8(); // algorithm
                    const userKey = string();
                    const hostKey = hostbound ? string() : null;
                    if (pos === data.length) return { kind: "SSH login", user, userKey, hostKey };
                }
            }
        } catch (e) {
            // fall through
        }
        return { kind: "Unknown data" };
    }

    async function fingerprint(keyBlob) {
        const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", keyBlob));
        return "SHA256:" + btoa(String.fromCharCode(...hash)).replace(/=+$/, "");
    }

    /** The key's SSH public key blob (records from before RSA support hold the raw Ed25519 key). */
    function publicBlob(record) {
        const key = new Uint8Array(record.publicKey);
        if (record.type) return key;
        const ssh = sshString("ssh-ed25519");
        const blob = new Uint8Array(ssh.length + 4 + key.length);
        blob.set(ssh);
        blob.set(sshString(key), ssh.length);
        return blob;
    }

    const sameBytes = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

    /**
     * Refuses to sign when the card says something the payload doesn't: the card is rendered by the
     * server, the payload is what actually gets signed.
     */
    async function checkCard(card, data, record) {
        const actual = describe(data);
        const claimed = card.dataset;
        const mismatch = (what) => new Error(`the request doesn't match what is shown (${what}); not signed`);
        if (actual.kind !== claimed.kind) throw mismatch("kind");
        if (actual.kind === "Signature" && actual.namespace !== claimed.namespace) throw mismatch("purpose");
        if (actual.kind === "SSH login") {
            if (actual.user !== claimed.user) throw mismatch("user");
            if (actual.hostKey && await fingerprint(actual.hostKey) !== claimed.hostKey) throw mismatch("host");
            // A login naming another key than the one signing is shown with a warning; it must be.
            if (!sameBytes(actual.userKey, publicBlob(record)) && claimed.warning !== "true") {
                throw mismatch("key");
            }
        }
    }

    // --- sign requests (start page) --------------------------------------------------------------

    async function approve(card) {
        // Created in another tab since this page loaded? (Safari may then refuse the prompt; tap again.)
        const id = card.dataset.key;
        const found = () => vault.keys.get(id) ?? legacy.get(id);
        const record = found() ?? await reload().then(found);
        if (!record) throw new Error("this key isn't synced, and isn't stored in this browser");
        const data = b64url.decode(card.dataset.payload);
        // Checked while the passkey prompt is up (Safari needs the prompt straight from the tap), and
        // awaited before the key is decrypted.
        const checked = checkCard(card, data, record);
        checked.catch(() => {}); // reported by sign(), not as an unhandled rejection
        const signature = await sign(record, data, card.dataset.hash, checked);
        // Repeated while the connection fails: the server accepts the same signature again, so a lost
        // answer can't turn into "already answered".
        const error = card.querySelector("[data-sign-error]");
        const response = await window.sshaPost(`/sign/${card.dataset.request}/approve`,
            new URLSearchParams({ signature: b64url.encode(signature) }), {
                onRetry: () => { error.textContent = "Poor connection, still sending…"; error.hidden = false; },
            });
        error.hidden = true;
        if (response.status === 404) throw new Error("this request was already answered or has expired");
        if (!response.ok) throw new Error(`server answered HTTP ${response.status}`);
        // The server removes the card from every open page once the request is answered; do not wait for
        // the stream, which may be down.
        card.remove();
    }

    const CANCELLED = "Cancelled, or no passkey on this device holds the SSH keys.";

    document.addEventListener("click", (e) => {
        const button = e.target.closest("[data-ssh-approve], [data-vault-approve]");
        if (!button) return;
        const card = button.closest(".sign");
        const error = card.querySelector("[data-sign-error]");
        error.hidden = true;
        card.querySelectorAll("button").forEach((b) => { b.disabled = true; });
        (button.hasAttribute("data-vault-approve") ? giveKeys(card) : approve(card)).catch((err) => {
            console.error(err);
            error.textContent = err.name === "NotAllowedError" ? CANCELLED : err.message;
            error.hidden = false;
            card.querySelectorAll("button").forEach((b) => { b.disabled = false; });
        });
    });

    // --- keys page -------------------------------------------------------------------------------

    function showError(err, id = "error", action = "create the key") {
        console.error(err);
        const el = document.getElementById(id);
        el.textContent = err.name === "NotAllowedError" ? CANCELLED : `Couldn't ${action}: ${err.message}`;
        el.hidden = false;
    }

    function keyStatus(li) {
        const id = li.dataset.sshKey;
        const el = li.querySelector("[data-ssh-device]");
        const show = (text, ok) => {
            el.textContent = text;
            el.classList.toggle("ok", ok);
            el.classList.toggle("bad", !ok);
        };
        if (vault.keys.has(id)) {
            show(canOpenHere() ? "synced, usable on this device" : "synced, not on this device yet", canOpenHere());
        } else if (legacy.has(id)) {
            show("only in this browser", true);
            const sync = li.querySelector("[data-ssh-sync]");
            sync.hidden = false;
            sync.addEventListener("click", () => {
                sync.disabled = true;
                syncKey(legacy.get(id)).then(() => location.reload(), (err) => {
                    showError(err, "error", "sync the key");
                    sync.disabled = false;
                });
            });
        } else {
            show("only on another device: sync it there", false);
        }
    }

    /** The "this device" box: offers to get the synced keys here, and waits for another device's answer. */
    async function deviceStatus() {
        const box = document.querySelector("[data-vault-device]");
        const button = box.querySelector("[data-vault-unlock]");
        const waiting = box.querySelector("[data-vault-waiting]");
        const wait = (request) => {
            button.hidden = true;
            box.querySelector("[data-vault-code]").textContent = request.code;
            waiting.hidden = false;
            receiveKeys(request).then(() => location.reload(), (err) => {
                showError(err, "device-error", "get the keys");
                waiting.hidden = true;
                button.hidden = false;
            });
        };
        if (!vault.slots.length || canOpenHere()) return;
        box.hidden = false;
        button.addEventListener("click", () => {
            document.getElementById("device-error").hidden = true;
            button.disabled = true;
            askForKeys().then((request) => {
                button.disabled = false;
                if (request) wait(request); else location.reload();
            }, (err) => {
                showError(err, "device-error", "get the keys");
                button.disabled = false;
            });
        });
        const pending = await getJoin();
        if (pending) wait(pending);
    }

    document.addEventListener("DOMContentLoaded", () => {
        const form = document.querySelector("[data-ssh-new-key]");
        if (!form) return;

        loaded.then(() => {
            document.querySelectorAll("[data-ssh-key]").forEach(keyStatus);
            return deviceStatus();
        }).catch((err) => showError(err, "error", "load the keys"));

        form.addEventListener("submit", (e) => {
            e.preventDefault();
            createKey(form.label.value.trim()).then(() => location.reload(), showError);
        });

        const importForm = document.querySelector("[data-ssh-import]");
        importForm.file.addEventListener("change", async () => {
            const file = importForm.file.files[0];
            if (file) importForm.key.value = await file.text();
        });
        importForm.addEventListener("submit", (e) => {
            e.preventDefault();
            document.getElementById("import-error").hidden = true;
            const button = importForm.querySelector("button");
            button.disabled = true;
            button.textContent = "Importing…";
            importKey(importForm.key.value, importForm.passphrase.value, importForm.label.value.trim())
                .then(() => {
                    importForm.reset();
                    location.reload();
                }, (err) => {
                    showError(err, "import-error", "import the key");
                    button.disabled = false;
                    button.textContent = "Import";
                });
        });

        document.querySelectorAll("[data-ssh-delete]").forEach((del) => del.addEventListener("submit", (e) => {
            e.preventDefault();
            if (!confirm("Delete this key from all your devices? It can't be recovered.")) return;
            const id = del.closest("[data-ssh-key]").dataset.sshKey;
            deleteLegacyKey(id).then(() => del.submit(), showError);
        }));

        if (!window.PublicKeyCredential || !crypto.subtle) {
            showError(new Error("this browser lacks passkeys or WebCrypto"));
        }
    });
})();
