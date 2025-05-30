// gist-sync.js - GitHub Gist synchronization system for NutriSnap
// This module handles all cloud storage and offline sync functionality

class GistStorage {
    constructor() {
        // Initialize with null values - will be set during auth
        this.token = null;
        this.gistId = null;
        this.username = null;
        
        // Sync state management
        this.syncInProgress = false;
        this.lastSyncTime = null;
        this.syncQueue = [];
        this.retryCount = 0;
        this.maxRetries = 5;
        this.retryDelay = 1000; // Start with 1 second
        
        // Version management
        this.currentAppVersion = '1.1.0'; // Increment this with each app update
        this.dataVersion = '1.0.0'; // Increment when data structure changes
        
        // Encryption key for token storage
        this.encryptionKey = this.getOrCreateEncryptionKey();
        
        // Initialize the storage system
        this.initialize();
    }
    
    async initialize() {
        // Check for existing authentication
        const storedAuth = this.getStoredAuth();
        if (storedAuth) {
            try {
                this.token = storedAuth.token;
                this.username = storedAuth.username;
                this.gistId = storedAuth.gistId;
                
                // Verify token is still valid
                await this.verifyAuthentication();
            } catch (error) {
                console.error('Auth verification failed:', error);
                this.handleAuthError(error);
            }
        }
        
        // Set up event listeners for online/offline
        window.addEventListener('online', () => this.handleOnline());
        window.addEventListener('offline', () => this.handleOffline());
        
        // Initialize IndexedDB for robust local storage
        try {
            await this.initializeLocalDB();
        } catch (error) {
            console.error('Failed to initialize local database:', error);
            this.showError('Storage initialization failed. Some features may not work properly.');
        }
        
        // Check if we need to sync
        if (navigator.onLine && this.token) {
            this.syncData();
        }
        
        // Load sync queue from persistent storage
        this.loadSyncQueue();
    }
    
    // Authentication flow
    async authenticate() {
        // Guide user through GitHub OAuth process
        const clientId = 'YOUR_GITHUB_OAUTH_APP_CLIENT_ID'; // You'll need to create this
        const redirectUri = 'https://tyleribs1976.github.io/nutrisnap/auth-callback.html';
        const scope = 'gist'; // We only need gist access
        
        // For now, we'll use personal access token approach
        // In production, implement proper OAuth flow
        try {
            const token = await this.promptForToken();
            
            if (token) {
                this.token = token;
                const authSuccess = await this.verifyAuthentication();
                
                if (authSuccess) {
                    await this.findOrCreateGist();
                    this.saveAuth();
                    return true;
                } else {
                    this.showError('Authentication failed. Please check your token and try again.');
                    return false;
                }
            }
            
            return false;
        } catch (error) {
            console.error('Authentication error:', error);
            this.showError('Authentication failed: ' + (error.message || 'Unknown error'));
            return false;
        }
    }
    
    async promptForToken() {
        // Create a modal to get GitHub token
        const modal = document.createElement('div');
        modal.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.8);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 10000;
            padding: 20px;
        `;
        
        modal.innerHTML = `
            <div style="background: white; border-radius: 20px; padding: 30px; max-width: 500px; width: 100%;">
                <h2 style="margin-bottom: 20px;">🔐 Enable Cloud Backup</h2>
                <p style="margin-bottom: 20px;">To backup your meals to GitHub, you need a personal access token.</p>
                
                <ol style="text-align: left; margin-bottom: 20px;">
                    <li>Go to <a href="https://github.com/settings/tokens/new" target="_blank">GitHub Settings</a></li>
                    <li>Create a token with 'gist' scope</li>
                    <li>Copy and paste it below</li>
                </ol>
                
                <input type="password" id="github-token" placeholder="Paste your GitHub token here" 
                       style="width: 100%; padding: 10px; margin-bottom: 20px; border: 1px solid #ddd; border-radius: 5px;">
                
                <div style="display: flex; gap: 10px;">
                    <button id="save-token" style="flex: 1; padding: 10px; background: #4F46E5; color: white; border: none; border-radius: 5px; cursor: pointer;">
                        Save Token
                    </button>
                    <button id="cancel-token" style="flex: 1; padding: 10px; background: #666; color: white; border: none; border-radius: 5px; cursor: pointer;">
                        Cancel
                    </button>
                </div>
                
                <p style="margin-top: 20px; font-size: 12px; color: #666;">
                    Your token is stored securely and never shared. You can revoke it anytime on GitHub.
                </p>
            </div>
        `;
        
        document.body.appendChild(modal);
        
        return new Promise((resolve) => {
            document.getElementById('save-token').onclick = () => {
                const token = document.getElementById('github-token').value.trim();
                modal.remove();
                resolve(token);
            };
            
            document.getElementById('cancel-token').onclick = () => {
                modal.remove();
                resolve(null);
            };
        });
    }
    
    async verifyAuthentication() {
        try {
            const response = await fetch('https://api.github.com/user', {
                headers: {
                    'Authorization': `token ${this.token}`,
                    'Accept': 'application/vnd.github.v3+json'
                }
            });
            
            if (response.ok) {
                const user = await response.json();
                this.username = user.login;
                return true;
            } else {
                // Handle different error codes
                if (response.status === 401) {
                    this.showError('Authentication failed: Invalid or expired token');
                    this.clearAuth();
                } else if (response.status === 403) {
                    // Rate limit exceeded
                    const resetTime = response.headers.get('X-RateLimit-Reset');
                    if (resetTime) {
                        const resetDate = new Date(resetTime * 1000);
                        this.showError(`Rate limit exceeded. Try again after ${resetDate.toLocaleTimeString()}`);
                    } else {
                        this.showError('Rate limit exceeded. Please try again later.');
                    }
                } else {
                    this.showError(`GitHub API error: ${response.status}`);
                }
                return false;
            }
        } catch (error) {
            console.error('Auth verification failed:', error);
            this.showError('Network error during authentication. Please check your connection.');
            return false;
        }
    }
    
    async findOrCreateGist() {
        // First, try to find existing NutriSnap gist
        try {
            const response = await fetch('https://api.github.com/gists', {
                headers: {
                    'Authorization': `token ${this.token}`,
                    'Accept': 'application/vnd.github.v3+json'
                }
            });
            
            if (!response.ok) {
                throw new Error(`GitHub API error: ${response.status}`);
            }
            
            const gists = await response.json();
            const nutriSnapGist = gists.find(g => g.description === 'NutriSnap Data - Do not delete');
            
            if (nutriSnapGist) {
                this.gistId = nutriSnapGist.id;
                console.log('Found existing NutriSnap gist:', this.gistId);
            } else {
                // Create new gist
                await this.createNewGist();
            }
        } catch (error) {
            console.error('Failed to find/create gist:', error);
            this.showError('Failed to access GitHub Gists. Please try again later.');
            throw error;
        }
    }
    
    async createNewGist() {
        const initialData = {
            version: this.dataVersion,
            appVersion: this.currentAppVersion,
            created: new Date().toISOString(),
            lastModified: new Date().toISOString(),
            deviceId: this.generateDeviceId(),
            meals: [],
            photos: {},
            stats: {
                totalMeals: 0,
                totalPhotos: 0,
                firstMeal: null,
                lastMeal: null
            }
        };
        
        try {
            const response = await fetch('https://api.github.com/gists', {
                method: 'POST',
                headers: {
                    'Authorization': `token ${this.token}`,
                    'Accept': 'application/vnd.github.v3+json',
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    description: 'NutriSnap Data - Do not delete',
                    public: false,
                    files: {
                        'nutrisnap-data.json': {
                            content: JSON.stringify(initialData, null, 2)
                        },
                        'nutrisnap-photos.json': {
                            content: JSON.stringify({}, null, 2)
                        },
                        'sync-log.json': {
                            content: JSON.stringify({
                                syncHistory: [],
                                lastSync: new Date().toISOString()
                            }, null, 2)
                        }
                    }
                })
            });
            
            if (response.ok) {
                const gist = await response.json();
                this.gistId = gist.id;
                console.log('Created new NutriSnap gist:', this.gistId);
            } else {
                throw new Error(`Failed to create gist: ${response.status}`);
            }
        } catch (error) {
            console.error('Error creating gist:', error);
            this.showError('Failed to create backup storage. Please try again later.');
            throw error;
        }
    }
    
    // Local storage with IndexedDB
    async initializeLocalDB() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open('NutriSnapSync', 2);
            
            request.onerror = () => reject(request.error);
            request.onsuccess = () => {
                this.localDB = request.result;
                resolve();
            };
            
            request.onupgradeneeded = (event) => {
                const db = event.target.result;
                
                // Meals store
                if (!db.objectStoreNames.contains('meals')) {
                    const mealStore = db.createObjectStore('meals', { keyPath: 'id' });
                    mealStore.createIndex('syncStatus', 'syncStatus');
                    mealStore.createIndex('timestamp', 'timestamp');
                }
                
                // Photos store (separate for efficiency)
                if (!db.objectStoreNames.contains('photos')) {
                    const photoStore = db.createObjectStore('photos', { keyPath: 'id' });
                    photoStore.createIndex('mealId', 'mealId');
                }
                
                // Sync metadata
                if (!db.objectStoreNames.contains('syncMeta')) {
                    db.createObjectStore('syncMeta', { keyPath: 'key' });
                }
            };
        });
    }
    
    // Save meal locally with sync queue
    async saveMealLocally(meal) {
        try {
            const transaction = this.localDB.transaction(['meals', 'photos'], 'readwrite');
            const mealStore = transaction.objectStore('meals');
            const photoStore = transaction.objectStore('photos');
            
            // Mark as pending sync
            meal.syncStatus = 'pending';
            meal.localSaveTime = new Date().toISOString();
            
            // Save meal
            await mealStore.put(meal);
            
            // Save photos separately
            for (const photo of meal.photos) {
                await photoStore.put({
                    id: photo.id,
                    mealId: meal.id,
                    type: photo.type,
                    dataUrl: photo.dataUrl,
                    metadata: photo.metadata,
                    analysis: photo.analysis
                });
            }
            
            // Add to sync queue
            this.syncQueue.push(meal.id);
            this.saveSyncQueue();
            
            // Attempt sync if online
            if (navigator.onLine && this.token) {
                this.syncData();
            }
            
            return true;
        } catch (error) {
            console.error('Error saving meal locally:', error);
            this.showError('Failed to save meal data locally.');
            return false;
        }
    }
    
    // Main sync function
    async syncData() {
        if (this.syncInProgress || !this.token || !this.gistId) return;
        
        this.syncInProgress = true;
        this.notifySyncStatus('syncing');
        
        try {
            console.log('Starting sync...');
            
            // Get current gist data
            const remoteData = await this.fetchGistData();
            
            // Get local pending meals
            const pendingMeals = await this.getPendingMeals();
            
            if (pendingMeals.length === 0) {
                console.log('No pending meals to sync');
                this.syncInProgress = false;
                this.notifySyncStatus('synced');
                return;
            }
            
            // Merge data (local changes win)
            const mergedData = await this.mergeData(remoteData, pendingMeals);
            
            // Update gist
            await this.updateGist(mergedData);
            
            // Mark local meals as synced
            await this.markMealsSynced(pendingMeals);
            
            // Update sync metadata
            this.lastSyncTime = new Date().toISOString();
            await this.updateSyncMetadata();
            
            // Reset retry count on success
            this.retryCount = 0;
            
            console.log('Sync completed successfully');
            
            // Notify UI
            this.notifySyncStatus('synced', { mealsSynced: pendingMeals.length });
            
        } catch (error) {
            console.error('Sync failed:', error);
            
            // Handle different error types
            if (error.name === 'NetworkError' || error.message.includes('network')) {
                // Network error - will retry when online
                this.notifySyncStatus('error', { error: 'Network error. Will retry when online.' });
            } else if (error.status === 401) {
                // Authentication error
                this.handleAuthError(error);
            } else if (error.status === 403 && error.message.includes('rate limit')) {
                // Rate limit error
                this.handleRateLimitError(error);
            } else {
                // Other errors - implement retry with exponential backoff
                if (this.retryCount < this.maxRetries) {
                    this.retryCount++;
                    const delay = this.retryDelay * Math.pow(2, this.retryCount - 1);
                    console.log(`Retrying sync in ${delay}ms (attempt ${this.retryCount})`);
                    
                    this.notifySyncStatus('error', { 
                        error: `Sync error. Retrying in ${Math.round(delay/1000)} seconds...` 
                    });
                    
                    setTimeout(() => {
                        this.syncInProgress = false;
                        this.syncData();
                    }, delay);
                } else {
                    // Max retries reached
                    this.notifySyncStatus('error', { 
                        error: 'Sync failed after multiple attempts. Please try again later.' 
                    });
                }
            }
        } finally {
            if (this.retryCount === 0) {
                this.syncInProgress = false;
            }
        }
    }
    
    async fetchGistData() {
        try {
            const response = await fetch(`https://api.github.com/gists/${this.gistId}`, {
                headers: {
                    'Authorization': `token ${this.token}`,
                    'Accept': 'application/vnd.github.v3+json'
                }
            });
            
            if (!response.ok) {
                const error = new Error('Failed to fetch gist');
                error.status = response.status;
                throw error;
            }
            
            const gist = await response.json();
            
            // Check if the expected files exist
            if (!gist.files['nutrisnap-data.json']) {
                throw new Error('Data file not found in gist');
            }
            
            const dataContent = gist.files['nutrisnap-data.json'].content;
            
            // Photos might be in multiple files or a single file
            let photosContent = '{}';
            if (gist.files['nutrisnap-photos.json']) {
                photosContent = gist.files['nutrisnap-photos.json'].content;
            } else {
                // Check for chunked photo files
                const photoChunks = {};
                let chunkIndex = 0;
                
                while (gist.files[`nutrisnap-photos-${chunkIndex}.json`]) {
                    const chunkContent = gist.files[`nutrisnap-photos-${chunkIndex}.json`].content;
                    Object.assign(photoChunks, JSON.parse(chunkContent));
                    chunkIndex++;
                }
                
                if (chunkIndex > 0) {
                    photosContent = JSON.stringify(photoChunks);
                }
            }
            
            return {
                data: JSON.parse(dataContent),
                photos: JSON.parse(photosContent)
            };
        } catch (error) {
            console.error('Error fetching gist data:', error);
            throw error;
        }
    }
    
    async mergeData(remoteData, localPendingMeals) {
        // Start with remote data
        const merged = { ...remoteData.data };
        const mergedPhotos = { ...remoteData.photos };
        
        // Add local pending meals
        for (const meal of localPendingMeals) {
            // Add meal to array
            const existingIndex = merged.meals.findIndex(m => m.id === meal.id);
            if (existingIndex >= 0) {
                // Update existing (local wins)
                merged.meals[existingIndex] = meal;
            } else {
                // Add new
                merged.meals.push(meal);
            }
            
            // Add photos
            for (const photo of meal.photos) {
                mergedPhotos[photo.id] = {
                    mealId: meal.id,
                    type: photo.type,
                    dataUrl: photo.dataUrl,
                    metadata: photo.metadata
                };
            }
        }
        
        // Update metadata
        merged.lastModified = new Date().toISOString();
        merged.appVersion = this.currentAppVersion;
        merged.stats = this.calculateStats(merged.meals);
        
        // Sort meals by timestamp
        merged.meals.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        
        return { data: merged, photos: mergedPhotos };
    }
    
    async updateGist(mergedData) {
        // Split photos into chunks if too large
        const photoChunks = this.chunkPhotos(mergedData.photos);
        
        const files = {
            'nutrisnap-data.json': {
                content: JSON.stringify(mergedData.data, null, 2)
            },
            'sync-log.json': {
                content: JSON.stringify({
                    syncHistory: [
                        {
                            timestamp: new Date().toISOString(),
                            deviceId: this.generateDeviceId(),
                            mealsUpdated: mergedData.data.meals.length,
                            photosUpdated: Object.keys(mergedData.photos).length
                        }
                    ],
                    lastSync: new Date().toISOString()
                }, null, 2)
            }
        };
        
        // Add photo files
        if (photoChunks.length === 1) {
            files['nutrisnap-photos.json'] = {
                content: JSON.stringify(mergedData.photos, null, 2)
            };
        } else {
            // Multiple photo files if data is large
            photoChunks.forEach((chunk, index) => {
                files[`nutrisnap-photos-${index}.json`] = {
                    content: JSON.stringify(chunk, null, 2)
                };
            });
        }
        
        try {
            const response = await fetch(`https://api.github.com/gists/${this.gistId}`, {
                method: 'PATCH',
                headers: {
                    'Authorization': `token ${this.token}`,
                    'Accept': 'application/vnd.github.v3+json',
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ files })
            });
            
            if (!response.ok) {
                const error = new Error('Failed to update gist');
                error.status = response.status;
                throw error;
            }
        } catch (error) {
            console.error('Error updating gist:', error);
            throw error;
        }
    }
    
    chunkPhotos(photos) {
        // GitHub has a 1MB limit per file
        // Split photos into chunks if needed
        const maxSize = 900000; // ~900KB to be safe
        const chunks = [];
        let currentChunk = {};
        let currentSize = 0;
        
        for (const [id, photo] of Object.entries(photos)) {
            const photoSize = JSON.stringify(photo).length;
            
            if (currentSize + photoSize > maxSize && Object.keys(currentChunk).length > 0) {
                chunks.push(currentChunk);
                currentChunk = {};
                currentSize = 0;
            }
            
            currentChunk[id] = photo;
            currentSize += photoSize;
        }
        
        if (Object.keys(currentChunk).length > 0) {
            chunks.push(currentChunk);
        }
        
        return chunks.length > 0 ? chunks : [{}];
    }
    
    async getPendingMeals() {
        try {
            const transaction = this.localDB.transaction(['meals', 'photos'], 'readonly');
            const mealStore = transaction.objectStore('meals');
            const photoStore = transaction.objectStore('photos');
            
            // Get all pending meals
            const pendingMeals = [];
            const index = mealStore.index('syncStatus');
            const request = index.openCursor(IDBKeyRange.only('pending'));
            
            return new Promise((resolve) => {
                request.onsuccess = async (event) => {
                    const cursor = event.target.result;
                    if (cursor) {
                        const meal = cursor.value;
                        
                        // Get photos for this meal
                        const photos = [];
                        const photoIndex = photoStore.index('mealId');
                        const photoRequest = photoIndex.getAll(meal.id);
                        
                        photoRequest.onsuccess = () => {
                            meal.photos = photoRequest.result;
                            pendingMeals.push(meal);
                        };
                        
                        cursor.continue();
                    } else {
                        // Wait a bit for all photo requests to complete
                        setTimeout(() => resolve(pendingMeals), 100);
                    }
                };
                
                request.onerror = (event) => {
                    console.error('Error getting pending meals:', event.target.error);
                    resolve([]);
                };
            });
        } catch (error) {
            console.error('Error getting pending meals:', error);
            return [];
        }
    }
    
    async markMealsSynced(meals) {
        try {
            const transaction = this.localDB.transaction(['meals'], 'readwrite');
            const mealStore = transaction.objectStore('meals');
            
            for (const meal of meals) {
                meal.syncStatus = 'synced';
                meal.lastSyncTime = new Date().toISOString();
                await mealStore.put(meal);
                
                // Remove from sync queue
                this.syncQueue = this.syncQueue.filter(id => id !== meal.id);
            }
            
            // Save updated sync queue
            this.saveSyncQueue();
        } catch (error) {
            console.error('Error marking meals as synced:', error);
            throw error;
        }
    }
    
    calculateStats(meals) {
        if (meals.length === 0) {
            return {
                totalMeals: 0,
                totalPhotos: 0,
                firstMeal: null,
                lastMeal: null
            };
        }
        
        const totalPhotos = meals.reduce((sum, meal) => sum + meal.photos.length, 0);
        const sortedMeals = [...meals].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
        
        return {
            totalMeals: meals.length,
            totalPhotos: totalPhotos,
            firstMeal: sortedMeals[0].timestamp,
            lastMeal: sortedMeals[sortedMeals.length - 1].timestamp,
            averagePhotosPerMeal: Math.round(totalPhotos / meals.length * 10) / 10,
            contextsUsed: [...new Set(meals.map(m => m.context))]
        };
    }
    
    // Token encryption and security
    getOrCreateEncryptionKey() {
        let key = localStorage.getItem('nutrisnap_encryption_key');
        if (!key) {
            // Generate a random key
            const array = new Uint8Array(32);
            window.crypto.getRandomValues(array);
            key = Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
            localStorage.setItem('nutrisnap_encryption_key', key);
        }
        return key;
    }
    
    encryptToken(token) {
        try {
            // Simple XOR encryption (in production, use Web Crypto API)
            const encrypted = [];
            for (let i = 0; i < token.length; i++) {
                const charCode = token.charCodeAt(i) ^ this.encryptionKey.charCodeAt(i % this.encryptionKey.length);
                encrypted.push(String.fromCharCode(charCode));
            }
            return btoa(encrypted.join(''));
        } catch (error) {
            console.error('Encryption error:', error);
            return null;
        }
    }
    
    decryptToken(encryptedToken) {
        try {
            const encrypted = atob(encryptedToken);
            const decrypted = [];
            for (let i = 0; i < encrypted.length; i++) {
                const charCode = encrypted.charCodeAt(i) ^ this.encryptionKey.charCodeAt(i % this.encryptionKey.length);
                decrypted.push(String.fromCharCode(charCode));
            }
            return decrypted.join('');
        } catch (error) {
            console.error('Decryption error:', error);
            return null;
        }
    }
    
    // Utility functions
    generateDeviceId() {
        let deviceId = localStorage.getItem('nutrisnap_device_id');
        if (!deviceId) {
            deviceId = 'device_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
            localStorage.setItem('nutrisnap_device_id', deviceId);
        }
        return deviceId;
    }
    
    getStoredAuth() {
        try {
            const auth = localStorage.getItem('nutrisnap_auth');
            if (!auth) return null;
            
            const authData = JSON.parse(auth);
            
            // Decrypt token
            if (authData.encryptedToken) {
                authData.token = this.decryptToken(authData.encryptedToken);
                delete authData.encryptedToken;
            }
            
            return authData;
        } catch (error) {
            console.error('Error getting stored auth:', error);
            return null;
        }
    }
    
    saveAuth() {
        try {
            const auth = {
                username: this.username,
                gistId: this.gistId,
                encryptedToken: this.encryptToken(this.token),
                savedAt: new Date().toISOString()
            };
            localStorage.setItem('nutrisnap_auth', JSON.stringify(auth));
        } catch (error) {
            console.error('Error saving auth:', error);
            this.showError('Failed to save authentication data.');
        }
    }
    
    clearAuth() {
        this.token = null;
        this.username = null;
        this.gistId = null;
        localStorage.removeItem('nutrisnap_auth');
    }
    
    async updateSyncMetadata() {
        try {
            const transaction = this.localDB.transaction(['syncMeta'], 'readwrite');
            const store = transaction.objectStore('syncMeta');
            
            await store.put({
                key: 'lastSync',
                timestamp: this.lastSyncTime,
                deviceId: this.generateDeviceId()
            });
        } catch (error) {
            console.error('Error updating sync metadata:', error);
        }
    }
    
    loadSyncQueue() {
        try {
            const queue = localStorage.getItem('nutrisnap_sync_queue');
            this.syncQueue = queue ? JSON.parse(queue) : [];
        } catch (error) {
            console.error('Error loading sync queue:', error);
            this.syncQueue = [];
        }
    }
    
    saveSyncQueue() {
        try {
            localStorage.setItem('nutrisnap_sync_queue', JSON.stringify(this.syncQueue));
        } catch (error) {
            console.error('Error saving sync queue:', error);
        }
    }
    
    // Error handling
    handleAuthError(error) {
        console.error('Authentication error:', error);
        this.clearAuth();
        this.showError('Authentication failed. Please log in again.');
        this.notifySyncStatus('auth_error');
    }
    
    handleRateLimitError(error) {
        console.error('Rate limit error:', error);
        
        // Calculate retry time based on rate limit reset
        const resetTime = error.headers?.get('X-RateLimit-Reset');
        let retryDelay = 60000; // Default to 1 minute
        
        if (resetTime) {
            const resetDate = new Date(resetTime * 1000);
            const waitTime = resetDate - new Date();
            if (waitTime > 0) {
                retryDelay = waitTime + 1000; // Add 1 second buffer
            }
        }
        
        this.showError(`GitHub API rate limit exceeded. Will retry later.`);
        
        // Schedule retry
        setTimeout(() => {
            this.syncInProgress = false;
            this.syncData();
        }, retryDelay);
    }
    
    showError(message) {
        // Dispatch error event for UI to handle
        window.dispatchEvent(new CustomEvent('gist-sync-error', {
            detail: { message }
        }));
    }
    
    notifySyncStatus(status, detail = {}) {
        // Notify UI of sync status changes
        window.dispatchEvent(new CustomEvent('sync-status-changed', {
            detail: { 
                status,
                ...detail,
                timestamp: new Date().toISOString(),
                pendingItems: this.syncQueue.length
            }
        }));
    }
    
    // Event handlers
    handleOnline() {
        console.log('Connection restored - attempting sync');
        this.notifySyncStatus('online');
        if (this.token && this.syncQueue.length > 0) {
            this.syncData();
        }
    }
    
    handleOffline() {
        console.log('Connection lost - working offline');
        this.notifySyncStatus('offline');
    }
    
    // Public API for the main app
    async enableCloudBackup() {
        const success = await this.authenticate();
        if (success) {
            // Sync any existing local data
            await this.syncData();
            return true;
        }
        return false;
    }
    
    async saveMeal(meal) {
        // Save locally first
        const saved = await this.saveMealLocally(meal);
        
        // Return sync status
        return {
            saved,
            pendingSync: !navigator.onLine || !this.token || this.syncQueue.length > 0
        };
    }
    
    isAuthenticated() {
        return !!this.token;
    }
    
    getSyncStatus() {
        return {
            authenticated: this.isAuthenticated(),
            syncInProgress: this.syncInProgress,
            lastSync: this.lastSyncTime,
            pendingItems: this.syncQueue.length,
            online: navigator.onLine
        };
    }
}

// Initialize when loaded
window.GistStorage = GistStorage;
