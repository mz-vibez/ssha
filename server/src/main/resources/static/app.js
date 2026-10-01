// All rendering happens on the server; this only handles connection status, CSRF and expired
// sessions, and duplicate suppression after reconnects.
(function () {
    const status = (online) => {
        const el = document.getElementById("status");
        el.textContent = online ? "live" : "reconnecting…";
        el.classList.toggle("online", online);
    };

    const toLogin = () => { location.href = "/login"; };

    // Send the CSRF token Spring Security expects with every htmx request.
    document.addEventListener("htmx:configRequest", (e) => {
        const token = document.querySelector("meta[name=_csrf]").content;
        const header = document.querySelector("meta[name=_csrf_header]").content;
        e.detail.headers[header] = token;
    });
    // Expired session: the server answers htmx requests with 401 instead of a redirect.
    document.addEventListener("htmx:responseError", (e) => {
        if (e.detail.xhr.status === 401) toLogin();
    });

    document.addEventListener("htmx:sseOpen", () => status(true));
    document.addEventListener("htmx:sseError", () => {
        status(false);
        // EventSource can't see status codes, so ask whether the session is still valid.
        fetch("/", { method: "HEAD", headers: { "HX-Request": "true" } })
            .then((r) => { if (r.status === 401) toLogin(); })
            .catch(() => {});
    });
    document.addEventListener("htmx:sseBeforeMessage", (e) => {
        // A reconnect resends every pending sign request; skip the ones already shown.
        const card = /^<section[^>]*\sid="(sign-[^"]+)"/.exec(e.detail.data);
        if (card && document.getElementById(card[1])) e.preventDefault();
    });
})();
