// The start page's plumbing; all rendering happens on the server. This keeps the event stream alive on a
// bad connection, shows requests that arrived by push before the stream is up, and posts the cards'
// buttons (deny, accept) with CSRF and retries. Plain fetch and EventSource: no library to download.
(function () {
    const approvals = document.getElementById("approvals");
    const status = (online) => {
        const el = document.getElementById("status");
        el.textContent = online ? "live" : "reconnecting…";
        el.classList.toggle("online", online);
    };
    const toLogin = () => { location.href = "/login"; };
    const csrfHeaders = () => {
        const token = document.querySelector("meta[name=_csrf]").content;
        const header = document.querySelector("meta[name=_csrf_header]").content;
        return { [header]: token, "HX-Request": "true" };
    };

    /**
     * POSTs, repeating while the connection fails or a proxy answers 502/503/504, until `giveUpAfter`
     * ms have passed. Other answers (404 expired, 401 signed out, ...) are final. `onRetry` is told
     * about each repeat. Safe because the server's answers are idempotent for a given request.
     */
    async function post(url, body, { giveUpAfter = 55000, onRetry } = {}) {
        const deadline = Date.now() + giveUpAfter;
        for (let attempt = 0; ; attempt++) {
            try {
                const response = await fetch(url, { method: "POST", headers: csrfHeaders(), body });
                if (response.status === 401) toLogin();
                if (![502, 503, 504].includes(response.status) || Date.now() >= deadline) return response;
            } catch (e) {
                if (Date.now() >= deadline) throw e;
            }
            onRetry?.(attempt + 1);
            await new Promise((r) => setTimeout(r, Math.min(500 * 2 ** attempt, 4000)));
        }
    }
    window.sshaPost = post;

    // --- cards -----------------------------------------------------------------------------------

    const template = document.createElement("template");

    function parse(html) {
        template.innerHTML = html;
        return [...template.content.children];
    }

    /** Adds the cards in `html`, or removes the ones it marks with data-remove. Known cards are kept. */
    function apply(html, { cached = false } = {}) {
        for (const el of parse(html)) {
            if (el.hasAttribute("data-remove")) {
                document.getElementById(el.id)?.remove();
                continue;
            }
            const existing = document.getElementById(el.id);
            if (existing) {
                delete existing.dataset.cached; // the server confirmed it
                continue;
            }
            if (cached) el.dataset.cached = "1";
            approvals.append(el);
        }
    }

    approvals.addEventListener("click", async (e) => {
        const button = e.target.closest("[data-post]");
        if (!button) return;
        const card = button.closest("section");
        card.querySelectorAll("button").forEach((b) => { b.disabled = true; });
        try {
            const response = await post(button.dataset.post);
            if (!response.ok && response.status !== 404) throw new Error("HTTP " + response.status);
            // Answered: the server removes the card from every open page. A 404 means it already was.
            if (response.status === 404) card.remove();
        } catch (err) {
            console.error(err);
            card.querySelectorAll("button").forEach((b) => { b.disabled = false; });
            const error = card.querySelector("[data-sign-error]");
            if (error) {
                error.textContent = "No connection; try again.";
                error.hidden = false;
            }
        }
    });

    // Requests the service worker kept from push messages: shown at once, then confirmed (or dropped) by
    // the stream. Anything older than a request lives is gone anyway.
    const REQUEST_LIFETIME_MS = 60 * 1000;
    async function showPushed() {
        if (!window.caches) return;
        const cache = await caches.open("ssha-cards");
        for (const request of await cache.keys()) {
            const response = await cache.match(request);
            const at = Number(response.headers.get("x-at"));
            if (Date.now() - at > REQUEST_LIFETIME_MS) {
                await cache.delete(request);
            } else {
                apply(await response.text(), { cached: true });
            }
        }
    }
    showPushed().catch(() => {});

    // --- event stream ----------------------------------------------------------------------------

    // The server sends an event every 20 s; a stream that says nothing for this long is dead even if the
    // browser doesn't know yet (common when a phone switches networks).
    const SILENCE_LIMIT_MS = 45 * 1000;
    let source = null;
    let lastEvent = 0;
    let retry = 0;
    let retryTimer = null;

    function connect() {
        clearTimeout(retryTimer);
        source?.close();
        const stream = new EventSource("/stream");
        source = stream;
        lastEvent = Date.now();
        const alive = () => { lastEvent = Date.now(); };
        stream.onopen = () => { alive(); retry = 0; status(true); };
        stream.addEventListener("ping", alive);
        stream.addEventListener("sign", (e) => { alive(); apply(e.data); });
        stream.addEventListener("synced", () => {
            alive();
            // Pending requests have all been sent: cards shown from a push that did not come are gone.
            approvals.querySelectorAll("[data-cached]").forEach((card) => card.remove());
        });
        stream.onerror = () => {
            status(false);
            stream.close();
            // EventSource can't see status codes, so ask whether the session is still valid.
            fetch("/", { method: "HEAD", headers: { "HX-Request": "true" }, signal: AbortSignal.timeout(5000) })
                .then((r) => { if (r.status === 401) toLogin(); })
                .catch(() => {});
            // Quick retries (a bad connection is what this is for), never longer than 5 s apart.
            retryTimer = setTimeout(connect, Math.min(500 * 2 ** retry++, 5000));
        };
    }

    // Reconnect now, instead of waiting for the next retry or the silence timer, when the phone
    // comes back to the page or gets its network back.
    const reconnectNow = () => { retry = 0; connect(); };
    document.addEventListener("visibilitychange", () => {
        if (document.visibilityState === "visible") {
            showPushed().catch(() => {});
            if (Date.now() - lastEvent > 10000) reconnectNow();
        }
    });
    window.addEventListener("online", reconnectNow);
    setInterval(() => {
        if (document.visibilityState === "visible" && Date.now() - lastEvent > SILENCE_LIMIT_MS) {
            status(false);
            reconnectNow();
        }
    }, 5000);

    connect();
})();
