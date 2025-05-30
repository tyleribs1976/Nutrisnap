const CACHE_NAME = 'nutrisnap-v1';
const urlsToCache = [
  './',
  './index.html',
  './manifest.json',
  './icon-32.png',
  './icon-16.png',
  './icon-180.png',
  './icon-192.png',
  './icon-512.png'
];

// Database sync queue
const DB_NAME = 'nutrisnap-db';
const SYNC_STORE_NAME = 'sync-queue';

// Install event - cache app shell files
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(urlsToCache))
  );
  self.skipWaiting();
});

// Activate event - clean up old caches
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheName !== CACHE_NAME) {
            return caches.delete(cacheName);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

// Fetch event - serve from cache, fall back to network
self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;
  
  // Skip non-GET requests and API calls
  if (event.request.url.includes('/api/')) {
    return;
  }
  
  event.respondWith(
    caches.match(event.request)
      .then(response => {
        // Return cached response if found
        if (response) {
          return response;
        }
        
        // Clone the request - request can only be used once
        const fetchRequest = event.request.clone();
        
        // Make network request and cache the response
        return fetch(fetchRequest)
          .then(response => {
            // Check if valid response
            if (!response || response.status !== 200 || response.type !== 'basic') {
              return response;
            }
            
            // Clone the response - response can only be used once
            const responseToCache = response.clone();
            
            // Add response to cache
            caches.open(CACHE_NAME)
              .then(cache => {
                cache.put(event.request, responseToCache);
              });
              
            return response;
          })
          .catch(() => {
            // If network fails, return offline page for document requests
            if (event.request.destination === 'document') {
              return new Response('<h1>You are offline</h1><p>Please check your connection and try again.</p>', {
                headers: { 'Content-Type': 'text/html' }
              });
            }
          });
      })
  );
});

// Background sync event
self.addEventListener('sync', event => {
  if (event.tag === 'nutrisnap-sync') {
    event.waitUntil(syncData());
  }
});

// Function to open IndexedDB
function openDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    
    request.onerror = event => {
      reject('Error opening database');
    };
    
    request.onsuccess = event => {
      resolve(event.target.result);
    };
    
    request.onupgradeneeded = event => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains(SYNC_STORE_NAME)) {
        db.createObjectStore(SYNC_STORE_NAME, { keyPath: 'id' });
      }
    };
  });
}

// Function to sync data with server
async function syncData() {
  try {
    // Get all clients
    const clients = await self.clients.matchAll();
    
    // Notify clients that sync is starting
    clients.forEach(client => {
      client.postMessage({
        type: 'SYNC_STATUS',
        status: 'syncing'
      });
    });
    
    // Get data from IndexedDB
    const db = await openDB();
    const transaction = db.transaction(SYNC_STORE_NAME, 'readwrite');
    const store = transaction.objectStore(SYNC_STORE_NAME);
    const items = await new Promise((resolve, reject) => {
      const request = store.getAll();
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    
    // If no items to sync, return
    if (!items || items.length === 0) {
      notifyClients(clients, 'synced');
      return;
    }
    
    // Process each item
    for (const item of items) {
      try {
        // Attempt to sync with server
        const response = await fetch('https://api.nutrisnap.example.com/meals', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(item)
        });
        
        if (response.ok) {
          // Remove from store if successful
          await new Promise((resolve, reject) => {
            const request = store.delete(item.id);
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
          });
        } else {
          console.error('Sync failed for item:', item.id);
        }
      } catch (error) {
        console.error('Error syncing item:', error);
      }
    }
    
    // Check if any items remain
    const remainingItems = await new Promise((resolve, reject) => {
      const request = store.count();
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    
    // Notify clients of sync status
    notifyClients(clients, remainingItems > 0 ? 'error' : 'synced');
    
  } catch (error) {
    console.error('Sync error:', error);
    
    // Get all clients
    const clients = await self.clients.matchAll();
    
    // Notify clients of sync error
    notifyClients(clients, 'error');
  }
}

// Function to notify all clients
function notifyClients(clients, status) {
  clients.forEach(client => {
    client.postMessage({
      type: 'SYNC_STATUS',
      status: status
    });
  });
}

// Listen for messages from clients
self.addEventListener('message', event => {
  if (event.data && event.data.type === 'SYNC_NOW') {
    syncData();
  }
});
