// The phone half of the SSH agent. Private keys must never leave the phone, so this part runs in the
// browser: keys are Ed25519 (WebCrypto), stored in IndexedDB encrypted with AES-GCM under a key
// derived from the passkey's PRF output. Every signature needs a fresh passkey tap to unlock the key.
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

    // --- IndexedDB: { id, label, type, publicKey, credentialId, salt, iv, ciphertext, created } ----
    // type is "ssh-ed25519" or "ssh-rsa"; publicKey is the SSH public key blob (records from before RSA
    // support have no type and hold the raw Ed25519 key). Either way it is the AES-GCM additional data.

    function store(mode, action) {
        return new Promise((resolve, reject) => {
            const open = indexedDB.open("ssha", 1);
            open.onupgradeneeded = () => open.result.createObjectStore("keys", { keyPath: "id" });
            open.onerror = () => reject(open.error);
            open.onsuccess = () => {
                const tx = open.result.transaction("keys", mode);
                const request = action(tx.objectStore("keys"));
                tx.oncomplete = () => { open.result.close(); resolve(request.result); };
                tx.onerror = () => { open.result.close(); reject(tx.error); };
            };
        });
    }
    const allKeys = () => store("readonly", (s) => s.getAll());
    const putKey = (record) => store("readwrite", (s) => s.put(record));
    const deleteKey = (id) => store("readwrite", (s) => s.delete(id));

    // Loaded up front: Safari only allows a passkey prompt straight from a tap, so the approve handler
    // must reach navigator.credentials.get() without waiting on IndexedDB first.
    let keys = new Map();
    const reload = () => allKeys().then((records) => { keys = new Map(records.map((r) => [r.id, r])); });
    const loaded = reload();

    // --- crypto ----------------------------------------------------------------------------------

    /** One passkey tap: returns the PRF output for `salt` (and which passkey produced it). */
    async function passkeySecret(salt, credentialId) {
        const cred = await navigator.credentials.get({
            publicKey: {
                challenge: crypto.getRandomValues(new Uint8Array(32)),
                userVerification: "required",
                allowCredentials: credentialId ? [{ type: "public-key", id: credentialId }] : [],
                extensions: { prf: { eval: { first: salt } } },
            },
        });
        const secret = cred.getClientExtensionResults().prf?.results?.first;
        if (!secret) {
            throw new Error("this passkey can't protect SSH keys (its provider doesn't support the PRF extension)");
        }
        return { secret, credentialId: new Uint8Array(cred.rawId) };
    }

    async function wrappingKey(secret, salt) {
        const material = await crypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveKey"]);
        return crypto.subtle.deriveKey(
            { name: "HKDF", hash: "SHA-256", salt, info: new TextEncoder().encode("ssha ssh key v1") },
            material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
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
        await storeKey(label, "ssh-ed25519", pkcs8, blob);
    }

    async function importKey(text, passphrase, label) {
        const { type, pkcs8, publicKey, comment } = await window.sshaKeyImport.read(text, passphrase);
        await storeKey((label || comment.trim() || "imported").slice(0, 100), type, pkcs8, publicKey);
    }

    /**
     * Encrypts `pkcs8` under the passkey (one tap), registers the public key blob and keeps the key in
     * IndexedDB.
     */
    async function storeKey(label, type, pkcs8, publicKey) {
        const salt = crypto.getRandomValues(new Uint8Array(32));
        const { secret, credentialId } = await passkeySecret(salt);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ciphertext = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv, additionalData: publicKey }, await wrappingKey(secret, salt), pkcs8);
        pkcs8.fill(0);

        const response = await fetch("/keys", {
            method: "POST",
            headers: { "Content-Type": "application/json", ...csrfHeaders() },
            body: JSON.stringify({ label, publicKey: b64url.encode(publicKey) }),
        });
        if (!response.ok) {
            throw new Error(response.status === 400 ? await response.text() || "the server refused the key"
                : `server answered HTTP ${response.status}`);
        }
        const { id } = await response.json();
        await putKey({ id, label, type, publicKey, credentialId, salt, iv, ciphertext, created: Date.now() });
        // Ask the browser not to evict this site's storage (best effort).
        await navigator.storage?.persist?.();
    }

    /**
     * @param hash    "SHA-256" or "SHA-512" for RSA keys, as the server says ssh asked for
     * @param checked settles once the request is checked; the key is only decrypted if it fulfils
     */
    async function sign(record, data, hash, checked) {
        const algorithm = record.type === "ssh-rsa" ? { name: "RSASSA-PKCS1-v1_5", hash } : { name: "Ed25519" };
        if (record.type === "ssh-rsa" && !hash) throw new Error("the request doesn't say which RSA hash to use");
        const { secret } = await passkeySecret(record.salt, record.credentialId);
        await checked;
        const pkcs8 = new Uint8Array(await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: record.iv, additionalData: record.publicKey },
            await wrappingKey(secret, record.salt), record.ciphertext));
        const key = await crypto.subtle.importKey("pkcs8", pkcs8, algorithm, false, ["sign"]);
        pkcs8.fill(0);
        return crypto.subtle.sign(algorithm, key, data);
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
        const record = keys.get(card.dataset.key) ?? await reload().then(() => keys.get(card.dataset.key));
        if (!record) throw new Error("this key isn't stored in this browser");
        const data = b64url.decode(card.dataset.payload);
        // Checked while the passkey prompt is up (Safari needs the prompt straight from the tap), and
        // awaited before the key is decrypted.
        const checked = checkCard(card, data, record);
        checked.catch(() => {}); // reported by sign(), not as an unhandled rejection
        const signature = await sign(record, data, card.dataset.hash, checked);
        const response = await fetch(`/sign/${card.dataset.request}/approve`, {
            method: "POST",
            headers: csrfHeaders(),
            body: new URLSearchParams({ signature: b64url.encode(signature) }),
        });
        if (response.status === 404) throw new Error("this request was already answered or has expired");
        if (!response.ok) throw new Error(`server answered HTTP ${response.status}`);
        // The server removes the card from every open page once the request is answered.
    }

    document.addEventListener("click", (e) => {
        const button = e.target.closest("[data-ssh-approve]");
        if (!button) return;
        const card = button.closest(".sign");
        const error = card.querySelector("[data-sign-error]");
        error.hidden = true;
        card.querySelectorAll("button").forEach((b) => { b.disabled = true; });
        approve(card).catch((err) => {
            console.error(err);
            error.textContent = err.name === "NotAllowedError" ? "Cancelled." : err.message;
            error.hidden = false;
            card.querySelectorAll("button").forEach((b) => { b.disabled = false; });
        });
    });

    // --- keys page -------------------------------------------------------------------------------

    function showError(err, id = "error", action = "create the key") {
        console.error(err);
        const el = document.getElementById(id);
        el.textContent = err.name === "NotAllowedError" ? "Cancelled." : `Couldn't ${action}: ${err.message}`;
        el.hidden = false;
    }

    document.addEventListener("DOMContentLoaded", () => {
        const form = document.querySelector("[data-ssh-new-key]");
        if (!form) return;

        loaded.then(() => {
            document.querySelectorAll("[data-ssh-key]").forEach((li) => {
                const here = keys.has(li.dataset.sshKey);
                const el = li.querySelector("[data-ssh-device]");
                el.textContent = here ? "stored in this browser" : "not in this browser — can't sign here";
                el.classList.add(here ? "ok" : "bad");
            });
        }, showError);

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
            if (!confirm("Delete this key? It can't be recovered.")) return;
            const id = del.closest("[data-ssh-key]").dataset.sshKey;
            deleteKey(id).then(() => del.submit(), showError);
        }));

        if (!window.PublicKeyCredential || !crypto.subtle) {
            showError(new Error("this browser lacks passkeys or WebCrypto"));
        }
    });
})();
