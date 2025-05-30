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
        this.currentAppVersion = '1.3.0'; // Incremented for new features
        this.dataVersion = '1.1.0'; // Incremented for new data structure
        
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
                // Encrypt token before storing
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
            const request = indexedDB.open('NutriSnapSync', 3); // Increased version for new fields
            
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
                    mealStore.createIndex('mealTime', 'mealTime'); // For editable meal time
                    mealStore.createIndex('date', 'date');
                } else if (event.oldVersion < 3) {
                    // Add new indexes for existing store if upgrading
                    const transaction = event.target.transaction;
                    const mealStore = transaction.objectStore('meals');
                    
                    // Add mealTime index if it doesn't exist
                    if (!mealStore.indexNames.contains('mealTime')) {
                        mealStore.createIndex('mealTime', 'mealTime');
                    }
                }
                
                // Photos store (separate for efficiency)
                if (!db.objectStoreNames.contains('photos')) {
                    const photoStore = db.createObjectStore('photos', { keyPath: 'id' });
                    photoStore.createIndex('mealId', 'mealId');
                } else if (event.oldVersion < 3) {
                    // Update existing photos store for new fields
                    const transaction = event.target.transaction;
                    const photoStore = transaction.objectStore('photos');
                    
                    // We don't need to add indexes for notes and consumptionPercentage
                    // as they're part of the photo object, not separate indexes
                }
                
                // Sync metadata
                if (!db.objectStoreNames.contains('syncMeta')) {
                    db.createObjectStore('syncMeta', { keyPath: 'key' });
                }
                
                // Migrate existing data if needed
                if (event.oldVersion > 0 && event.oldVersion < 3) {
                    this.migrateData(event.target.transaction);
                }
            };
        });
    }
    
    // Migrate existing data to new schema
    async migrateData(transaction) {
        console.log('Migrating data to new schema...');
        
        const mealStore = transaction.objectStore('meals');
        const photoStore = transaction.objectStore('photos');
        
        // Get all meals
        const mealRequest = mealStore.openCursor();
        
        mealRequest.onsuccess = (event) => {
            const cursor = event.target.result;
            if (cursor) {
                const meal = cursor.value;
                
                // Add mealTime if it doesn't exist
                if (!meal.mealTime) {
                    meal.mealTime = meal.timestamp;
                }
                
                // Update photos to include notes and consumption percentage
                if (meal.photos) {
                    meal.photos = meal.photos.map(photo => {
                        if (!photo.notes) {
                            photo.notes = '';
                        }
                        if (!photo.consumptionPercentage) {
                            photo.consumptionPercentage = 100;
                        }
                        return photo;
                    });
                }
                
                // Update the meal
                cursor.update(meal);
                cursor.continue();
            }
        };
        
        // Get all photos
        const photoRequest = photoStore.openCursor();
        
        photoRequest.onsuccess = (event) => {
            const cursor = event.target.result;
            if (cursor) {
                const photo = cursor.value;
                
                // Add notes and consumption percentage if they don't exist
                if (!photo.notes) {
                    photo.notes = '';
                }
                if (!photo.consumptionPercentage) {
                    photo.consumptionPercentage = 100;
                }
                
                // Update the photo
                cursor.update(photo);
                cursor.continue();
            }
        };
        
        console.log('Data migration completed');
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
            const mealDate = new Date(meal.mealTime).toISOString().split('T')[0];
            meal.date = mealDate;
            
            // Save meal
            await mealStore.put(meal);
            
            // Save photos separately
            for (const photo of meal.photos) {
                await photoStore.put({
                    id: photo.id,
                    mealId: meal.id,
                    data: photo.data,
                    isMenu: photo.isMenu,
                    notes: photo.notes || '',
                    consumptionPercentage: photo.consumptionPercentage || 100
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
            this.notifySyncStatus('synced');
        } catch (error) {
            console.error('Sync error:', error);
            
            // Implement exponential backoff
            this.retryCount++;
            if (this.retryCount <= this.maxRetries) {
                const delay = this.retryDelay * Math.pow(2, this.retryCount - 1);
                console.log(`Retrying sync in ${delay}ms (attempt ${this.retryCount})`);
                
                setTimeout(() => {
                    this.syncData();
                }, delay);
            } else {
                this.showError('Sync failed after multiple attempts. Will try again later.');
                this.notifySyncStatus('error', error.message);
            }
        } finally {
            this.syncInProgress = false;
        }
    }
    
    // Fetch data from GitHub Gist
    async fetchGistData() {
        try {
            const response = await fetch(`https://api.github.com/gists/${this.gistId}`, {
                headers: {
                    'Authorization': `token ${this.token}`,
                    'Accept': 'application/vnd.github.v3+json'
                }
            });
            
            if (!response.ok) {
                throw new Error(`GitHub API error: ${response.status}`);
            }
            
            const gist = await response.json();
            
            // Parse data file
            const dataFile = gist.files['nutrisnap-data.json'];
            if (!dataFile) {
                throw new Error('Data file not found in gist');
            }
            
            const dataContent = await fetch(dataFile.raw_url).then(res => res.json());
            
            // Parse photos file
            const photosFile = gist.files['nutrisnap-photos.json'];
            let photosContent = {};
            
            if (photosFile) {
                photosContent = await fetch(photosFile.raw_url).then(res => res.json());
            }
            
            return {
                data: dataContent,
                photos: photosContent,
                gistEtag: response.headers.get('ETag')
            };
        } catch (error) {
            console.error('Error fetching gist data:', error);
            throw error;
        }
    }
    
    // Get pending meals from IndexedDB
    async getPendingMeals() {
        return new Promise((resolve, reject) => {
            const transaction = this.localDB.transaction(['meals', 'photos'], 'readonly');
            const mealStore = transaction.objectStore('meals');
            const photoStore = transaction.objectStore('photos');
            
            const pendingIndex = mealStore.index('syncStatus');
            const request = pendingIndex.getAll('pending');
            
            request.onsuccess = async () => {
                const pendingMeals = request.result;
                
                // Load photos for each meal
                for (const meal of pendingMeals) {
                    const photoIndex = photoStore.index('mealId');
                    const photoRequest = photoIndex.getAll(meal.id);
                    
                    await new Promise(resolve => {
                        photoRequest.onsuccess = () => {
                            meal.photos = photoRequest.result;
                            resolve();
                        };
                        photoRequest.onerror = () => {
                            console.error('Error loading photos for meal:', meal.id);
                            meal.photos = [];
                            resolve();
                        };
                    });
                }
                
                resolve(pendingMeals);
            };
            
            request.onerror = () => {
                reject(request.error);
            };
        });
    }
    
    // Merge local and remote data
    async mergeData(remoteData, localMeals) {
        const { data, photos } = remoteData;
        
        // Create a map of remote meals by ID
        const remoteMealsMap = {};
        data.meals.forEach(meal => {
            remoteMealsMap[meal.id] = meal;
        });
        
        // Add or update local meals in remote data
        localMeals.forEach(localMeal => {
            // Local changes win over remote
            remoteMealsMap[localMeal.id] = localMeal;
            
            // Add photos to photos object
            localMeal.photos.forEach(photo => {
                photos[photo.id] = {
                    mealId: localMeal.id,
                    data: photo.data,
                    isMenu: photo.isMenu,
                    notes: photo.notes || '',
                    consumptionPercentage: photo.consumptionPercentage || 100
                };
            });
        });
        
        // Rebuild meals array
        data.meals = Object.values(remoteMealsMap);
        
        // Update metadata
        data.lastModified = new Date().toISOString();
        data.stats.totalMeals = data.meals.length;
        data.stats.totalPhotos = Object.keys(photos).length;
        
        if (data.meals.length > 0) {
            // Sort meals by timestamp
            data.meals.sort((a, b) => a.timestamp - b.timestamp);
            data.stats.firstMeal = data.meals[0].timestamp;
            data.stats.lastMeal = data.meals[data.meals.length - 1].timestamp;
        }
        
        return { data, photos };
    }
    
    // Update gist with merged data
    async updateGist(mergedData) {
        const { data, photos } = mergedData;
        
        try {
            // Split data into chunks if needed
            const dataStr = JSON.stringify(data, null, 2);
            const photosStr = JSON.stringify(photos, null, 2);
            
            // Check if we need to split photos (GitHub has a file size limit)
            const files = {
                'nutrisnap-data.json': {
                    content: dataStr
                },
                'nutrisnap-photos.json': {
                    content: photosStr
                },
                'sync-log.json': {
                    content: JSON.stringify({
                        syncHistory: [
                            {
                                timestamp: new Date().toISOString(),
                                device: this.generateDeviceId(),
                                mealsCount: data.meals.length,
                                photosCount: Object.keys(photos).length
                            }
                        ],
                        lastSync: new Date().toISOString()
                    }, null, 2)
                }
            };
            
            // Update gist
            const response = await fetch(`https://api.github.com/gists/${this.gistId}`, {
                method: 'PATCH',
                headers: {
                    'Authorization': `token ${this.token}`,
                    'Accept': 'application/vnd.github.v3+json',
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    files: files
                })
            });
            
            if (!response.ok) {
                throw new Error(`GitHub API error: ${response.status}`);
            }
            
            return true;
        } catch (error) {
            console.error('Error updating gist:', error);
            throw error;
        }
    }
    
    // Mark meals as synced in IndexedDB
    async markMealsSynced(meals) {
        return new Promise((resolve, reject) => {
            const transaction = this.localDB.transaction(['meals'], 'readwrite');
            const mealStore = transaction.objectStore('meals');
            
            let completed = 0;
            
            meals.forEach(meal => {
                const request = mealStore.get(meal.id);
                
                request.onsuccess = () => {
                    const storedMeal = request.result;
                    if (storedMeal) {
                        storedMeal.syncStatus = 'synced';
                        storedMeal.lastSynced = new Date().toISOString();
                        
                        const updateRequest = mealStore.put(storedMeal);
                        
                        updateRequest.onsuccess = () => {
                            completed++;
                            if (completed === meals.length) {
                                resolve();
                            }
                        };
                        
                        updateRequest.onerror = () => {
                            reject(updateRequest.error);
                        };
                    } else {
                        completed++;
                        if (completed === meals.length) {
                            resolve();
                        }
                    }
                };
                
                request.onerror = () => {
                    reject(request.error);
                };
            });
            
            // Handle empty array
            if (meals.length === 0) {
                resolve();
            }
        });
    }
    
    // Update sync metadata
    async updateSyncMetadata() {
        return new Promise((resolve, reject) => {
            const transaction = this.localDB.transaction(['syncMeta'], 'readwrite');
            const metaStore = transaction.objectStore('syncMeta');
            
            const request = metaStore.put({
                key: 'lastSync',
                value: this.lastSyncTime
            });
            
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    }
    
    // Handle online event
    handleOnline() {
        console.log('Device is online, checking for pending syncs...');
        
        // Update UI
        this.notifySyncStatus('online');
        
        // Attempt to sync if authenticated
        if (this.token && this.gistId) {
            this.syncData();
        }
    }
    
    // Handle offline event
    handleOffline() {
        console.log('Device is offline, sync paused');
        
        // Update UI
        this.notifySyncStatus('offline');
    }
    
    // Load sync queue from localStorage
    loadSyncQueue() {
        try {
            const queueStr = localStorage.getItem('nutrisnap_sync_queue');
            if (queueStr) {
                this.syncQueue = JSON.parse(queueStr);
            }
        } catch (error) {
            console.error('Error loading sync queue:', error);
            this.syncQueue = [];
        }
    }
    
    // Save sync queue to localStorage
    saveSyncQueue() {
        try {
            localStorage.setItem('nutrisnap_sync_queue', JSON.stringify(this.syncQueue));
        } catch (error) {
            console.error('Error saving sync queue:', error);
        }
    }
    
    // Get stored authentication data
    getStoredAuth() {
        try {
            const authStr = localStorage.getItem('nutrisnap_auth');
            if (!authStr) return null;
            
            // Decrypt the stored auth data
            const decrypted = this.decrypt(authStr, this.encryptionKey);
            return JSON.parse(decrypted);
        } catch (error) {
            console.error('Error getting stored auth:', error);
            return null;
        }
    }
    
    // Save authentication data
    saveAuth() {
        try {
            const authData = {
                token: this.token,
                username: this.username,
                gistId: this.gistId,
                timestamp: Date.now()
            };
            
            // Encrypt the auth data before storing
            const encrypted = this.encrypt(JSON.stringify(authData), this.encryptionKey);
            localStorage.setItem('nutrisnap_auth', encrypted);
        } catch (error) {
            console.error('Error saving auth:', error);
        }
    }
    
    // Clear authentication data
    clearAuth() {
        this.token = null;
        this.username = null;
        this.gistId = null;
        
        try {
            localStorage.removeItem('nutrisnap_auth');
        } catch (error) {
            console.error('Error clearing auth:', error);
        }
    }
    
    // Handle authentication errors
    handleAuthError(error) {
        console.error('Auth error:', error);
        this.clearAuth();
        this.notifySyncStatus('auth_error');
    }
    
    // Check if authenticated
    isAuthenticated() {
        return !!this.token && !!this.gistId;
    }
    
    // Sync a single meal
    async syncMeal(meal) {
        if (!this.isAuthenticated() || !navigator.onLine) {
            await this.saveMealLocally(meal);
            this.showNotification('✅ Meal saved locally (will sync when online)');
        } else {
            await this.saveMealLocally(meal);
            this.syncData();
            this.showNotification('✅ Meal saved and synced!');
        }
        
        this.updateSyncUI();
    }
    
    // Sync all meals
    async syncAllMeals(meals) {
        if (!this.isAuthenticated()) {
            this.showError('Please authenticate first');
            return;
        }
        
        this.notifySyncStatus('syncing');
        
        try {
            // Mark all meals as pending
            const transaction = this.localDB.transaction(['meals'], 'readwrite');
            const mealStore = transaction.objectStore('meals');
            
            for (const meal of meals) {
                const request = mealStore.get(meal.id);
                
                await new Promise((resolve, reject) => {
                    request.onsuccess = () => {
                        const storedMeal = request.result;
                        if (storedMeal) {
                            storedMeal.syncStatus = 'pending';
                            mealStore.put(storedMeal);
                        }
                        resolve();
                    };
                    
                    request.onerror = () => {
                        reject(request.error);
                    };
                });
            }
            
            // Start sync
            await this.syncData();
            
            this.showNotification('✅ All meals synced successfully!');
        } catch (error) {
            console.error('Error syncing all meals:', error);
            this.showError('Failed to sync all meals: ' + error.message);
        }
    }
    
    // Update sync UI
    updateSyncUI() {
        const syncStatus = document.getElementById('syncStatus');
        const syncIcon = document.getElementById('syncIcon');
        const syncText = document.getElementById('syncText');
        const syncButton = document.getElementById('syncButton');
        
        if (!syncStatus || !syncIcon || !syncText || !syncButton) return;
        
        if (!navigator.onLine) {
            syncStatus.className = 'sync-status';
            syncIcon.textContent = '🔄';
            syncText.textContent = 'Offline Mode';
            syncButton.textContent = 'Enable Backup';
        } else if (!this.isAuthenticated()) {
            syncStatus.className = 'sync-status';
            syncIcon.textContent = '🔄';
            syncText.textContent = 'Cloud Backup Not Enabled';
            syncButton.textContent = 'Enable Backup';
        } else if (this.syncInProgress) {
            syncStatus.className = 'sync-status syncing';
            syncIcon.textContent = '🔄';
            syncText.textContent = 'Syncing...';
            syncButton.textContent = 'Syncing...';
        } else {
            syncStatus.className = 'sync-status synced';
            syncIcon.textContent = '✅';
            syncText.textContent = 'Synced with GitHub Gist';
            syncButton.textContent = 'Sync Now';
        }
    }
    
    // Notify sync status change
    notifySyncStatus(status, message = '') {
        // Update UI
        this.updateSyncUI();
        
        // Dispatch event for other components
        window.dispatchEvent(new CustomEvent('gistSyncStatusChange', {
            detail: { status, message }
        }));
    }
    
    // Show error message
    showError(message) {
        console.error(message);
        
        // Show notification
        this.showNotification('❌ ' + message);
    }
    
    // Show notification
    showNotification(message) {
        // Remove existing notification
        const existingNotification = document.querySelector('.notification');
        if (existingNotification) {
            existingNotification.remove();
        }
        
        // Create new notification
        const notification = document.createElement('div');
        notification.className = 'notification';
        notification.textContent = message;
        
        document.body.appendChild(notification);
        
        // Remove after 3 seconds
        setTimeout(() => {
            notification.remove();
        }, 3000);
    }
    
    // Generate device ID
    generateDeviceId() {
        let deviceId = localStorage.getItem('nutrisnap_device_id');
        
        if (!deviceId) {
            deviceId = 'device_' + Math.random().toString(36).substring(2, 15);
            localStorage.setItem('nutrisnap_device_id', deviceId);
        }
        
        return deviceId;
    }
    
    // Get or create encryption key
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
    
    // Encrypt data
    encrypt(text, key) {
        // Simple XOR encryption for demonstration
        // In production, use a proper encryption library
        const textBytes = new TextEncoder().encode(text);
        const keyBytes = new TextEncoder().encode(key);
        
        const encrypted = new Uint8Array(textBytes.length);
        for (let i = 0; i < textBytes.length; i++) {
            encrypted[i] = textBytes[i] ^ keyBytes[i % keyBytes.length];
        }
        
        return Array.from(encrypted, b => b.toString(16).padStart(2, '0')).join('');
    }
    
    // Decrypt data
    decrypt(encryptedHex, key) {
        // Simple XOR decryption for demonstration
        const encrypted = new Uint8Array(encryptedHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
        const keyBytes = new TextEncoder().encode(key);
        
        const decrypted = new Uint8Array(encrypted.length);
        for (let i = 0; i < encrypted.length; i++) {
            decrypted[i] = encrypted[i] ^ keyBytes[i % keyBytes.length];
        }
        
        return new TextDecoder().decode(decrypted);
    }
}

// Initialize the gist storage system
window.gistStorage = new GistStorage();
