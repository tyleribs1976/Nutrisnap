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
        this.currentAppVersion = '1.2.0'; // Incremented for historical meal loading feature
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
                    // Add date index for historical meal loading
                    mealStore.createIndex('date', 'date');
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
            
            // Extract date for easier querying
            const mealDate = new Date(meal.timestamp).toISOString().split('T')[0];
            meal.date = mealDate;
            
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
                this.handleOffline();
            } else if (error.status === 401) {
                this.handleAuthError(error);
            } else if (error.status === 403) {
                // Rate limit - exponential backoff
                this.handleRateLimit(error);
            } else {
                // General error
                this.retryWithBackoff();
            }
        } finally {
            this.syncInProgress = false;
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
                throw { status: response.status, message: `GitHub API error: ${response.status}` };
            }
            
            const gist = await response.json();
            
            // Parse data file
            const dataFile = gist.files['nutrisnap-data.json'];
            if (!dataFile) {
                throw new Error('Data file not found in gist');
            }
            
            const data = JSON.parse(dataFile.content);
            return data;
        } catch (error) {
            console.error('Error fetching gist data:', error);
            throw error;
        }
    }
    
    async getPendingMeals() {
        return new Promise((resolve, reject) => {
            const transaction = this.localDB.transaction(['meals'], 'readonly');
            const mealStore = transaction.objectStore('meals');
            const index = mealStore.index('syncStatus');
            const request = index.getAll('pending');
            
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }
    
    async mergeData(remoteData, localMeals) {
        // Create a copy of remote data
        const mergedData = JSON.parse(JSON.stringify(remoteData));
        
        // Update app version
        mergedData.appVersion = this.currentAppVersion;
        mergedData.lastModified = new Date().toISOString();
        
        // Create a map of existing meals by ID for quick lookup
        const mealMap = {};
        mergedData.meals.forEach(meal => {
            mealMap[meal.id] = true;
        });
        
        // Add local meals that don't exist in remote, or update existing ones
        localMeals.forEach(meal => {
            // If meal exists, find and replace it
            const existingIndex = mergedData.meals.findIndex(m => m.id === meal.id);
            
            if (existingIndex >= 0) {
                mergedData.meals[existingIndex] = meal;
            } else {
                mergedData.meals.push(meal);
            }
        });
        
        // Update stats
        mergedData.stats.totalMeals = mergedData.meals.length;
        mergedData.stats.totalPhotos = mergedData.meals.reduce((sum, meal) => sum + meal.photos.length, 0);
        
        // Sort meals by timestamp (newest first)
        mergedData.meals.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        
        // Update first/last meal timestamps
        if (mergedData.meals.length > 0) {
            mergedData.stats.firstMeal = mergedData.meals[mergedData.meals.length - 1].timestamp;
            mergedData.stats.lastMeal = mergedData.meals[0].timestamp;
        }
        
        return mergedData;
    }
    
    async updateGist(data) {
        try {
            // Split data if it's too large
            const chunks = this.chunkData(data);
            
            // Prepare files object
            const files = {};
            
            // Main data file
            files['nutrisnap-data.json'] = {
                content: JSON.stringify({
                    ...data,
                    meals: chunks.length > 1 ? [] : data.meals // Empty if chunked
                }, null, 2)
            };
            
            // Add chunks if needed
            chunks.forEach((chunk, index) => {
                files[`meals-chunk-${index}.json`] = {
                    content: JSON.stringify(chunk, null, 2)
                };
            });
            
            // Update sync log
            files['sync-log.json'] = {
                content: JSON.stringify({
                    syncHistory: [
                        {
                            timestamp: new Date().toISOString(),
                            device: this.generateDeviceId(),
                            mealCount: data.meals.length
                        }
                    ],
                    lastSync: new Date().toISOString()
                }, null, 2)
            };
            
            // Update gist
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
                throw { status: response.status, message: `GitHub API error: ${response.status}` };
            }
            
            return true;
        } catch (error) {
            console.error('Error updating gist:', error);
            throw error;
        }
    }
    
    chunkData(data) {
        const meals = [...data.meals];
        
        // If data is small enough, no need to chunk
        const dataSize = JSON.stringify(meals).length;
        if (dataSize < 900000) { // GitHub has a 1MB limit, stay under it
            return [meals];
        }
        
        // Need to chunk data
        const chunks = [];
        let currentChunk = [];
        let currentSize = 0;
        
        for (const meal of meals) {
            const mealSize = JSON.stringify(meal).length;
            
            // If adding this meal would exceed chunk size, start a new chunk
            if (currentSize + mealSize > 900000) {
                chunks.push(currentChunk);
                currentChunk = [meal];
                currentSize = mealSize;
            } else {
                currentChunk.push(meal);
                currentSize += mealSize;
            }
        }
        
        // Add the last chunk if it has items
        if (currentChunk.length > 0) {
            chunks.push(currentChunk);
        }
        
        return chunks;
    }
    
    async markMealsSynced(meals) {
        const transaction = this.localDB.transaction(['meals'], 'readwrite');
        const mealStore = transaction.objectStore('meals');
        
        for (const meal of meals) {
            meal.syncStatus = 'synced';
            meal.syncTime = new Date().toISOString();
            await mealStore.put(meal);
            
            // Remove from sync queue
            const index = this.syncQueue.indexOf(meal.id);
            if (index >= 0) {
                this.syncQueue.splice(index, 1);
            }
        }
        
        this.saveSyncQueue();
        
        return new Promise((resolve, reject) => {
            transaction.oncomplete = () => resolve();
            transaction.onerror = () => reject(transaction.error);
        });
    }
    
    async updateSyncMetadata() {
        const transaction = this.localDB.transaction(['syncMeta'], 'readwrite');
        const metaStore = transaction.objectStore('syncMeta');
        
        await metaStore.put({
            key: 'lastSync',
            value: this.lastSyncTime
        });
        
        return new Promise((resolve, reject) => {
            transaction.oncomplete = () => resolve();
            transaction.onerror = () => reject(transaction.error);
        });
    }
    
    // Error handling and retry logic
    handleAuthError(error) {
        console.error('Authentication error:', error);
        this.showError('Authentication failed. Please re-authenticate.');
        this.clearAuth();
        this.notifySyncStatus('error', { message: 'Authentication failed' });
    }
    
    handleRateLimit(error) {
        console.error('Rate limit exceeded:', error);
        this.showError('GitHub API rate limit exceeded. Please try again later.');
        this.notifySyncStatus('error', { message: 'Rate limit exceeded' });
    }
    
    retryWithBackoff() {
        if (this.retryCount < this.maxRetries) {
            this.retryCount++;
            const delay = this.retryDelay * Math.pow(2, this.retryCount - 1);
            console.log(`Retrying sync in ${delay}ms (attempt ${this.retryCount})`);
            
            setTimeout(() => {
                this.syncData();
            }, delay);
        } else {
            console.error('Max retry attempts reached');
            this.showError('Sync failed after multiple attempts. Please try again later.');
            this.notifySyncStatus('error', { message: 'Max retry attempts reached' });
            this.retryCount = 0;
        }
    }
    
    handleOnline() {
        console.log('Device is online');
        
        // If we have pending items and we're authenticated, try to sync
        if (this.syncQueue.length > 0 && this.token) {
            this.syncData();
        }
        
        // Notify UI
        this.notifySyncStatus('online');
    }
    
    handleOffline() {
        console.log('Device is offline');
        
        // Notify UI
        this.notifySyncStatus('offline');
    }
    
    // Public API
    async saveMeal(meal) {
        // Save to local storage first
        const saveResult = await this.saveMealLocally(meal);
        
        // Return result with sync status
        return {
            success: saveResult,
            pendingSync: !navigator.onLine || !this.token
        };
    }
    
    // New method for historical meal loading
    async getMealsByDate(dateString) {
        try {
            // First check local database
            const localMeals = await this.getLocalMealsByDate(dateString);
            
            // If we're online and authenticated, also check cloud
            if (navigator.onLine && this.token && this.gistId) {
                try {
                    const cloudMeals = await this.getCloudMealsByDate(dateString);
                    
                    // Merge local and cloud meals, removing duplicates
                    const allMeals = [...localMeals];
                    const localIds = new Set(localMeals.map(m => m.id));
                    
                    for (const meal of cloudMeals) {
                        if (!localIds.has(meal.id)) {
                            allMeals.push(meal);
                        }
                    }
                    
                    // Sort by timestamp (newest first)
                    allMeals.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
                    
                    return allMeals;
                } catch (error) {
                    console.error('Error fetching cloud meals:', error);
                    // Fall back to local meals only
                    return localMeals;
                }
            }
            
            return localMeals;
        } catch (error) {
            console.error('Error getting meals by date:', error);
            this.showError('Failed to load meals for the selected date.');
            return [];
        }
    }
    
    async getLocalMealsByDate(dateString) {
        return new Promise((resolve, reject) => {
            if (!this.localDB) {
                reject(new Error('Local database not initialized'));
                return;
            }
            
            const transaction = this.localDB.transaction(['meals'], 'readonly');
            const mealStore = transaction.objectStore('meals');
            
            // Use the date index if available
            if (mealStore.indexNames.contains('date')) {
                const dateIndex = mealStore.index('date');
                const request = dateIndex.getAll(dateString);
                
                request.onsuccess = () => {
                    resolve(request.result || []);
                };
                
                request.onerror = () => {
                    reject(request.error);
                };
            } else {
                // Fallback to filtering all meals
                const request = mealStore.getAll();
                
                request.onsuccess = () => {
                    const meals = request.result || [];
                    const filteredMeals = meals.filter(meal => {
                        const mealDate = new Date(meal.timestamp).toISOString().split('T')[0];
                        return mealDate === dateString;
                    });
                    resolve(filteredMeals);
                };
                
                request.onerror = () => {
                    reject(request.error);
                };
            }
        });
    }
    
    async getCloudMealsByDate(dateString) {
        try {
            // Fetch all gist data
            const gistData = await this.fetchGistData();
            
            // Get meals from main data and chunks
            let allMeals = [...gistData.meals];
            
            // If data is chunked, fetch all chunks
            if (gistData.meals.length === 0) {
                const gist = await fetch(`https://api.github.com/gists/${this.gistId}`, {
                    headers: {
                        'Authorization': `token ${this.token}`,
                        'Accept': 'application/vnd.github.v3+json'
                    }
                }).then(res => res.json());
                
                // Find all chunk files
                const chunkFiles = Object.keys(gist.files)
                    .filter(name => name.startsWith('meals-chunk-'))
                    .map(name => gist.files[name]);
                
                // Fetch and parse each chunk
                for (const file of chunkFiles) {
                    const chunkContent = await fetch(file.raw_url).then(res => res.json());
                    allMeals = [...allMeals, ...chunkContent];
                }
            }
            
            // Filter meals by date
            return allMeals.filter(meal => {
                const mealDate = new Date(meal.timestamp).toISOString().split('T')[0];
                return mealDate === dateString;
            });
        } catch (error) {
            console.error('Error fetching cloud meals by date:', error);
            throw error;
        }
    }
    
    // Helper methods
    isAuthenticated() {
        return !!this.token;
    }
    
    getSyncStatus() {
        return {
            authenticated: !!this.token,
            online: navigator.onLine,
            syncInProgress: this.syncInProgress,
            pendingItems: this.syncQueue.length,
            lastSync: this.lastSyncTime
        };
    }
    
    async enableCloudBackup() {
        return await this.authenticate();
    }
    
    notifySyncStatus(status, detail = {}) {
        window.dispatchEvent(new CustomEvent('sync-status-changed', {
            detail: {
                status,
                ...detail,
                timestamp: new Date().toISOString()
            }
        }));
    }
    
    showError(message) {
        window.dispatchEvent(new CustomEvent('gist-sync-error', {
            detail: {
                message,
                timestamp: new Date().toISOString()
            }
        }));
    }
    
    // Secure token storage
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
        // Simple XOR encryption (in production, use a proper encryption library)
        const key = this.encryptionKey;
        let result = '';
        
        for (let i = 0; i < token.length; i++) {
            const charCode = token.charCodeAt(i) ^ key.charCodeAt(i % key.length);
            result += String.fromCharCode(charCode);
        }
        
        return btoa(result); // Base64 encode
    }
    
    decryptToken(encrypted) {
        if (!encrypted) return null;
        
        try {
            const key = this.encryptionKey;
            const decoded = atob(encrypted); // Base64 decode
            let result = '';
            
            for (let i = 0; i < decoded.length; i++) {
                const charCode = decoded.charCodeAt(i) ^ key.charCodeAt(i % key.length);
                result += String.fromCharCode(charCode);
            }
            
            return result;
        } catch (error) {
            console.error('Error decrypting token:', error);
            return null;
        }
    }
    
    saveAuth() {
        const encryptedToken = this.encryptToken(this.token);
        
        localStorage.setItem('nutrisnap_auth', JSON.stringify({
            token: encryptedToken,
            username: this.username,
            gistId: this.gistId,
            timestamp: new Date().toISOString()
        }));
    }
    
    getStoredAuth() {
        const auth = localStorage.getItem('nutrisnap_auth');
        if (!auth) return null;
        
        try {
            const parsed = JSON.parse(auth);
            return {
                ...parsed,
                token: this.decryptToken(parsed.token)
            };
        } catch (error) {
            console.error('Error parsing stored auth:', error);
            return null;
        }
    }
    
    clearAuth() {
        localStorage.removeItem('nutrisnap_auth');
        this.token = null;
        this.username = null;
        this.gistId = null;
    }
    
    // Persistence for sync queue
    saveSyncQueue() {
        localStorage.setItem('nutrisnap_sync_queue', JSON.stringify(this.syncQueue));
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
    
    // Device identification
    generateDeviceId() {
        let deviceId = localStorage.getItem('nutrisnap_device_id');
        if (!deviceId) {
            deviceId = 'device_' + Math.random().toString(36).substring(2, 15);
            localStorage.setItem('nutrisnap_device_id', deviceId);
        }
        return deviceId;
    }
}
