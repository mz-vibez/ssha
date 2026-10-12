// Service worker, for a phone on a bad connection:
//  - keeps the last start page, so opening the app (e.g. from a notification) works when the network is slow
//    or down. The page's other files have the content hash in their URL and are kept by the browser itself;
//  - shows push notifications for waiting requests, keeping the request's card for the page;
//  - opens the start page when a notification is tapped.
const SHELL = "ssha-shell-v2";
const CARDS = "ssha-cards";
const PAGE_WAIT_MS = 3000;

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil((async () => {
    for (const name of await caches.keys()) {
        if (name !== SHELL && name !== CARDS) await caches.delete(name);
    }
    await self.clients.claim();
})()));

self.addEventListener("fetch", (event) => {
    const url = new URL(event.request.url);
    if (event.request.method === "GET" && url.origin === location.origin
        && event.request.mode === "navigate" && url.pathname === "/") {
        event.respondWith(pageOrCached(event.request));
    }
});

// The start page: from the network, but if that is slow or down, the last copy (the page is the same for
// everything except the CSRF token, which stays valid for the whole session). A signed-out answer
// (redirect to /login) is never kept.
async function pageOrCached(request) {
    const cache = await caches.open(SHELL);
    const network = fetch(request).then((response) => {
        if (response.ok && !response.redirected) cache.put("/", response.clone());
        return response;
    });
    const cached = await cache.match("/");
    if (!cached) return network;
    network.catch(() => {});
    return Promise.race([
        network,
        new Promise((resolve) => setTimeout(() => resolve(cached), PAGE_WAIT_MS)),
    ]).catch(() => cached);
}

self.addEventListener("message", (event) => {
    // Sent when signing out: nothing of the account stays on the phone.
    if (event.data === "clear") event.waitUntil(Promise.all([caches.delete(CARDS), caches.delete(SHELL)]));
});

self.addEventListener("push", (event) => {
    let message = {};
    try {
        message = event.data ? event.data.json() : {};
    } catch (e) {
        // Shown with the defaults below: a push must always show a notification.
    }
    event.waitUntil((async () => {
        // Requests expire after a minute or two; clear notifications of ones that are long gone.
        for (const old of await self.registration.getNotifications()) {
            if (Date.now() - (old.data?.at || 0) > 5 * 60 * 1000) old.close();
        }
        if (message.card && message.tag) {
            // The page shows it straight away when opened; the stream then confirms it.
            const cards = await caches.open(CARDS);
            await cards.put("/card/" + message.tag, new Response(message.card, {
                headers: { "Content-Type": "text/html", "x-at": String(message.at || Date.now()) },
            }));
        }
        await self.registration.showNotification(message.title || "ssha", {
            body: message.body || "A request is waiting for your approval.",
            tag: message.tag,
            icon: "/icon-192.png",
            data: { at: message.at || Date.now() },
        });
    })());
});

self.addEventListener("notificationclick", (event) => {
    event.notification.close();
    event.waitUntil((async () => {
        const windows = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
        const start = windows.find((w) => new URL(w.url).pathname === "/");
        if (start) return start.focus();
        if (windows.length > 0) {
            const page = await windows[0].focus();
            return page.navigate("/").catch(() => self.clients.openWindow("/"));
        }
        return self.clients.openWindow("/");
    })());
});
