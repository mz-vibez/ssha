// Passkey ceremonies. WebAuthn is a browser API, so this is the one part that has to run client-side:
// fetch options from Spring Security, ask the authenticator, post the result back. Request/response
// shapes follow Spring Security's own spring-security-webauthn.js.
(function () {
    const b64url = {
        encode(buffer) {
            return btoa(String.fromCharCode(...new Uint8Array(buffer)))
                .replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
        },
        decode(value) {
            const bin = atob(value.replace(/-/g, "+").replace(/_/g, "/"));
            return Uint8Array.from(bin, (c) => c.charCodeAt(0)).buffer;
        },
    };

    function csrfHeaders() {
        const token = document.querySelector("meta[name=_csrf]")?.content;
        const header = document.querySelector("meta[name=_csrf_header]")?.content;
        return token && header ? { [header]: token } : {};
    }

    async function post(url, body) {
        const response = await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json", ...csrfHeaders() },
            body: body === undefined ? undefined : JSON.stringify(body),
        });
        if (!response.ok) throw new Error(`server answered HTTP ${response.status}`);
        return response.json();
    }

    async function signIn() {
        const options = await post("/webauthn/authenticate/options");
        const cred = await navigator.credentials.get({
            publicKey: {
                ...options,
                challenge: b64url.decode(options.challenge),
                allowCredentials: (options.allowCredentials || []).map((c) => ({ ...c, id: b64url.decode(c.id) })),
            },
        });
        const r = cred.response;
        const result = await post("/login/webauthn", {
            id: cred.id,
            rawId: b64url.encode(cred.rawId),
            response: {
                authenticatorData: b64url.encode(r.authenticatorData),
                clientDataJSON: b64url.encode(r.clientDataJSON),
                signature: b64url.encode(r.signature),
                userHandle: r.userHandle ? b64url.encode(r.userHandle) : undefined,
            },
            credType: cred.type,
            clientExtensionResults: cred.getClientExtensionResults(),
            authenticatorAttachment: cred.authenticatorAttachment,
        });
        if (!result.authenticated) throw new Error("sign-in was not accepted");
        return result.redirectUrl || "/";
    }

    async function register(label) {
        const options = await post("/webauthn/register/options");
        const cred = await navigator.credentials.create({
            publicKey: {
                ...options,
                user: { ...options.user, id: b64url.decode(options.user.id) },
                challenge: b64url.decode(options.challenge),
                excludeCredentials: (options.excludeCredentials || []).map((c) => ({ ...c, id: b64url.decode(c.id) })),
                // Some authenticators only offer PRF (used to encrypt SSH keys) when asked at creation.
                extensions: { ...options.extensions, prf: {} },
            },
        });
        // Spring Security only knows credProps; don't send it extension results it can't parse.
        const { credProps } = cred.getClientExtensionResults();
        const r = cred.response;
        const result = await post("/webauthn/register", {
            publicKey: {
                label,
                credential: {
                    id: cred.id,
                    rawId: b64url.encode(cred.rawId),
                    response: {
                        attestationObject: b64url.encode(r.attestationObject),
                        clientDataJSON: b64url.encode(r.clientDataJSON),
                        transports: r.getTransports ? r.getTransports() : [],
                    },
                    type: cred.type,
                    clientExtensionResults: credProps ? { credProps } : {},
                    authenticatorAttachment: cred.authenticatorAttachment,
                },
            },
        });
        if (!result.success) throw new Error("the server rejected the passkey");
    }

    function showError(err) {
        console.error(err);
        const el = document.getElementById("error");
        el.textContent = err.name === "NotAllowedError"
            ? "Cancelled, or no passkey for this site on this device."
            : err.name === "InvalidStateError"
                ? "This device already has a passkey for this account."
                : "Something went wrong: " + err.message;
        el.hidden = false;
    }

    document.addEventListener("DOMContentLoaded", () => {
        if (!window.PublicKeyCredential) {
            showError(new Error("this browser does not support passkeys"));
            return;
        }
        document.querySelector("[data-passkey-login]")?.addEventListener("click", () => {
            signIn().then((url) => { location.href = url; }, showError);
        });
        document.querySelector("[data-passkey-register]")?.addEventListener("submit", (e) => {
            e.preventDefault();
            register(e.target.label.value.trim()).then(() => location.reload(), showError);
        });
    });
})();
