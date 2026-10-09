// Installs the service worker (PWA + notifications) and manages this browser's push subscription:
// the start page offers to turn notifications on, and signing out turns them off for this browser.
(function () {
    if (!("serviceWorker" in navigator)) return;
    const ready = navigator.serviceWorker.register("/sw.js").then(() => navigator.serviceWorker.ready);

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

    function post(url, body) {
        const token = document.querySelector("meta[name=_csrf]")?.content;
        const header = document.querySelector("meta[name=_csrf_header]")?.content;
        return fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json", ...(token && header ? { [header]: token } : {}) },
            body: JSON.stringify(body),
        }).then((r) => {
            if (!r.ok) throw new Error(`server answered HTTP ${r.status}`);
        });
    }

    const supported = "PushManager" in window && "Notification" in window;
    const isIos = /iPhone|iPad|iPod/.test(navigator.userAgent)
        || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
    const standalone = matchMedia("(display-mode: standalone)").matches || navigator.standalone === true;

    async function currentSubscription() {
        const registration = await ready;
        const subscription = await registration.pushManager.getSubscription();
        if (!subscription) return null;
        // Made for another server key (e.g. the server's data was reset): useless, start over.
        const key = subscription.options?.applicationServerKey;
        const vapid = document.querySelector("meta[name=vapid-key]")?.content;
        if (key && vapid && b64url.encode(key) !== vapid) {
            await subscription.unsubscribe();
            return null;
        }
        return subscription;
    }

    // --- start page ----------------------------------------------------------------------------

    const banner = document.getElementById("push");
    if (banner) {
        const text = banner.querySelector("[data-push-text]");
        const button = banner.querySelector("[data-push-enable]");
        const show = (message, withButton) => {
            text.textContent = message;
            button.hidden = !withButton;
            banner.hidden = false;
        };

        async function enable() {
            const permission = await Notification.requestPermission();
            if (permission !== "granted") {
                show("Notifications are blocked for this site; allow them in the browser's settings.", false);
                return;
            }
            const registration = await ready;
            const subscription = await currentSubscription() || await registration.pushManager.subscribe({
                userVisibleOnly: true,
                applicationServerKey: b64url.decode(document.querySelector("meta[name=vapid-key]").content),
            });
            await post("/push/subscribe", subscription.toJSON());
            banner.hidden = true;
        }

        button.addEventListener("click", () => {
            button.disabled = true;
            enable().catch((err) => show("Couldn't turn on notifications: " + err.message, true))
                .finally(() => { button.disabled = false; });
        });

        (async () => {
            if (!supported) {
                if (isIos && !standalone) {
                    show("For notifications, add ssha to your Home Screen (Share → Add to Home Screen) and open it from there.", false);
                }
                return;
            }
            if (Notification.permission === "denied") {
                show("Notifications are blocked for this site; allow them in the browser's settings.", false);
                return;
            }
            const subscription = Notification.permission === "granted" ? await currentSubscription() : null;
            if (subscription) {
                // Keeps the server's copy current, e.g. after signing in to another account here.
                await post("/push/subscribe", subscription.toJSON());
            } else {
                show("Get a notification when a request is waiting, even with this page closed.", true);
            }
        })().catch(() => {});

        // Whatever the notifications announced is on this page now.
        const clearNotifications = () => {
            if (document.visibilityState !== "visible") return;
            ready.then((r) => r.getNotifications()).then((list) => list.forEach((n) => n.close())).catch(() => {});
        };
        clearNotifications();
        document.addEventListener("visibilitychange", clearNotifications);
    }

    // --- signing out ---------------------------------------------------------------------------

    document.querySelectorAll("form[action='/logout']").forEach((form) => {
        form.addEventListener("submit", (e) => {
            if (!supported || form.dataset.unsubscribed) return;
            e.preventDefault();
            const done = () => { form.dataset.unsubscribed = "1"; form.submit(); };
            const unsubscribe = currentSubscription().then(async (subscription) => {
                if (!subscription) return;
                await post("/push/unsubscribe", { endpoint: subscription.endpoint }).catch(() => {});
                await subscription.unsubscribe();
            });
            // The phone keeps no page, request or file of the account it signed out of.
            navigator.serviceWorker.controller?.postMessage("clear");
            window.caches?.delete("ssha-cards");
            // Never hold up signing out for long.
            Promise.race([unsubscribe, new Promise((r) => setTimeout(r, 2000))]).catch(() => {}).finally(done);
        });
    });
})();
