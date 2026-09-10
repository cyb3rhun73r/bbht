const CACHE = "bbht-v1";
const SHELL = ["/", "/assets/style.css", "/assets/app.js", "/manifest.json"];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)));
  self.skipWaiting();
});

self.addEventListener("activate", (e) => {
  self.clients.claim();
});

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (url.pathname.startsWith("/api/")) return; // never cache API calls
  e.respondWith(
    fetch(e.request).catch(() => caches.match(e.request))
  );
});
