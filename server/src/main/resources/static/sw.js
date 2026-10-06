// Service worker: shows push notifications for waiting requests and opens the start page when one is
// tapped. Nothing is cached; every page needs the server anyway.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));

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
