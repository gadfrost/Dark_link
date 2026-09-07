const CACHE_NAME = 'dark-link-cache-v2';
const urlsToCache = [
  '/',
  '/index.html',
  '/chat.html',
  '/profile.html'
];

// Installation du Service Worker et mise en cache des assets statiques
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        return cache.addAll(urlsToCache);
      })
  );
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(self.clients.claim());
});

// Interception des requêtes réseau
self.addEventListener('fetch', event => {
  // On ne gère que les requêtes GET locales pour le cache
  if (event.request.method === 'GET' && !event.request.url.includes('/api/')) {
    event.respondWith(
      caches.match(event.request)
        .then(response => {
          if (response) return response;
          return fetch(event.request);
        })
    );
  }
});

// Réception des notifications Push
self.addEventListener('push', event => {
  let data = { title: 'Nouveau message', body: 'Vous avez reçu un nouveau message.' };
  
  if (event.data) {
    try {
      data = event.data.json();
    } catch (e) {
      data.body = event.data.text();
    }
  }

  const options = {
    body: data.body,
    icon: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 512 512'%3E%3Crect width='512' height='512' fill='%231a6eff' rx='100'/%3E%3Cpath fill='%23fff' d='M256 120c-75.1 0-136 50.1-136 112 0 35.8 20.3 67.5 50.8 88.5l-14.4 43.1a8 8 0 0010.5 9.9l51.5-22.1c11.8 3.5 24.5 5.5 37.6 5.5 75.1 0 136-50.1 136-112S331.1 120 256 120z'/%3E%3C/svg%3E",
    badge: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 512 512'%3E%3Ccircle cx='256' cy='256' r='256' fill='%23fff'/%3E%3C/svg%3E",
    vibrate: [200, 100, 200],
    tag: data.tag || 'dark-link-notification',
    renotify: true,
    data: data.url || '/chat.html'
  };

  event.waitUntil(
    self.registration.showNotification(data.title, options)
  );
});

// Gestion du clic sur la notification
self.addEventListener('notificationclick', event => {
  event.notification.close();
  
  // Url à ouvrir
  const urlToOpen = new URL(event.notification.data || '/chat.html', self.location.origin).href;

  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(windowClients => {
      // Chercher si l'onglet est déjà ouvert
      for (let i = 0; i < windowClients.length; i++) {
        const client = windowClients[i];
        if (client.url === urlToOpen && 'focus' in client) {
          return client.focus();
        }
      }
      // Sinon on ouvre une nouvelle fenêtre
      if (clients.openWindow) {
        return clients.openWindow(urlToOpen);
      }
    })
  );
});
