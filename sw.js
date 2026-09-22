// webapp/sw.js
//
// A minimal service worker. Its only two jobs: (1) it's one of the
// requirements Android/Chrome checks before offering "Add to Home
// Screen," and (2) it caches the app's own files so the vault still
// opens without a network connection — reasonable for something that's
// entirely local anyway. It never touches your vault data: that lives in
// IndexedDB, which is a completely separate storage system from the
// Cache API used here.

const CACHE_NAME = 'simple-vault-shell-v1';
const APP_SHELL = [
  './',
  './index.html',
  './style.css',
  './app.js',
  './core/crypto.js',
  './core/vault.js',
  './manifest.json',
  './icons/icon-192.png',
  './icons/icon-512.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(APP_SHELL)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((names) => Promise.all(names.filter((n) => n !== CACHE_NAME).map((n) => caches.delete(n))))
      .then(() => self.clients.claim())
  );
});

// Cache-first for the app's own files, falling back to the network (and
// updating the cache) so a new deploy is picked up on the next load.
self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return;

  event.respondWith(
    caches.match(event.request).then((cached) => {
      const network = fetch(event.request)
        .then((response) => {
          if (response.ok) {
            caches.open(CACHE_NAME).then((cache) => cache.put(event.request, response.clone()));
          }
          return response;
        })
        .catch(() => cached);
      return cached || network;
    })
  );
});
