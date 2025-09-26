class ProctorService {
    constructor() {
        this.eventListeners = new Set();
        this.statusListeners = new Set();
        this.moduleData = new Map();
        this.isConnected = false;
        
        this.init();
    }
    
    init() {
        if (typeof window !== 'undefined' && window.proctorAPI) {
            this.setupEventListeners();
            this.isConnected = true;
            console.log('[ProctorService] Connected to ProctorAPI');
        } else {
            console.warn('[ProctorService] ProctorAPI not available');
        }
    }
    
    setupEventListeners() {
        // Subscribe to proctor events
        this.eventCleanup = window.proctorAPI.onEvent((data) => {
            this.handleProctorEvent(data);
        });
        
        // Subscribe to worker status changes
        this.statusCleanup = window.proctorAPI.onWorkerStatusChange((status) => {
            this.handleStatusChange(status);
        });
    }
    
    handleProctorEvent(data) {
        const { module, payload, timestamp } = data;
        
        console.log('[ProctorService] Received event for module:', module, 'with payload keys:', payload ? Object.keys(payload) : 'none');
        
        // Update module data
        this.moduleData.set(module, {
            ...payload,
            lastUpdated: timestamp
        });
        
        // Notify listeners
        this.eventListeners.forEach(listener => {
            try {
                listener(module, payload, timestamp);
            } catch (error) {
                console.error('[ProctorService] Error in event listener:', error);
            }
        });
    }
    
    handleStatusChange(status) {
        this.statusListeners.forEach(listener => {
            try {
                listener(status);
            } catch (error) {
                console.error('[ProctorService] Error in status listener:', error);
            }
        });
    }
    
    // Subscribe to proctor events
    onEvent(callback) {
        this.eventListeners.add(callback);
        
        // Return unsubscribe function
        return () => {
            this.eventListeners.delete(callback);
        };
    }
    
    // Subscribe to status changes
    onStatusChange(callback) {
        this.statusListeners.add(callback);
        
        return () => {
            this.statusListeners.delete(callback);
        };
    }
    
    // Get latest data for a specific module
    getModuleData(moduleName) {
        return this.moduleData.get(moduleName) || null;
    }
    
    // Get all module data
    getAllModuleData() {
        const data = {};
        for (const [module, payload] of this.moduleData.entries()) {
            data[module] = payload;
        }
        return data;
    }
    
    // Get worker status
    async getWorkerStatus() {
        if (!this.isConnected) return null;
        
        try {
            return await window.proctorAPI.getWorkerStatus();
        } catch (error) {
            console.error('[ProctorService] Error getting worker status:', error);
            return null;
        }
    }
    
    // Restart a worker
    async restartWorker(moduleName) {
        if (!this.isConnected) return false;
        
        try {
            await window.proctorAPI.restartWorker(moduleName);
            return true;
        } catch (error) {
            console.error('[ProctorService] Error restarting worker:', error);
            return false;
        }
    }

    // Start all workers (used when permissions are granted)
    async startAllWorkers() {
        if (!this.isConnected) return false;
        
        try {
            // Send command to start all workers
            return window.proctorAPI.sendCommand({ cmd: 'start-all-workers' });
        } catch (error) {
            console.error('[ProctorService] Error starting all workers:', error);
            return false;
        }
    }
    
    // Get system information
    async getSystemInfo() {
        if (!this.isConnected) return null;

        try {
            return await window.proctorAPI.getSystemInfo();
        } catch (error) {
            console.error('[ProctorService] Error getting system info:', error);
            return null;
        }
    }

    // Permission management methods
    async checkPermissions() {
        if (!this.isConnected) return null;

        try {
            return await window.proctorAPI.checkPermissions();
        } catch (error) {
            console.error('[ProctorService] Error checking permissions:', error);
            return null;
        }
    }

    async requestPermissions() {
        if (!this.isConnected) return null;

        try {
            return await window.proctorAPI.requestPermissions();
        } catch (error) {
            console.error('[ProctorService] Error requesting permissions:', error);
            return null;
        }
    }

    async requestSpecificPermission(permissionType) {
        if (!this.isConnected) return false;

        try {
            return await window.proctorAPI.requestSpecificPermission(permissionType);
        } catch (error) {
            console.error(`[ProctorService] Error requesting ${permissionType} permission:`, error);
            return false;
        }
    }

    async checkSpecificPermission(permissionType) {
        if (!this.isConnected) return false;

        try {
            return await window.proctorAPI.checkSpecificPermission(permissionType);
        } catch (error) {
            console.error(`[ProctorService] Error checking ${permissionType} permission:`, error);
            return false;
        }
    }
    
    // Clean up event listeners
    destroy() {
        if (this.eventCleanup) {
            this.eventCleanup();
        }
        if (this.statusCleanup) {
            this.statusCleanup();
        }
        
        this.eventListeners.clear();
        this.statusListeners.clear();
        this.moduleData.clear();
    }
    
    // Get module display information  
    getModuleInfo(moduleName) {
        const moduleInfo = {
            'process-watch': { name: 'Process Monitor', icon: '🔍', color: '#e74c3c' },
            'device-watch': { name: 'Device Monitor', icon: '💾', color: '#1abc9c' },
            'bt-watch': { name: 'Bluetooth', icon: '📶', color: '#9b59b6' },
            'screen-watch': { name: 'Screen Monitor', icon: '🖥️', color: '#f39c12' },
            'notification-blocker': { name: 'Notification Blocker', icon: '🔕', color: '#e67e22' },
            'vm-detect': { name: 'VM Detection', icon: '🖴', color: '#34495e' },
            'clipboard-worker': { name: 'Clipboard', icon: '📋', color: '#16a085' },
            'focus-idle-watch': { name: 'Focus & Idle Monitor', icon: '🎯', color: '#27ae60' },
            'recorder-overlay-watch': { name: 'Recording & Overlay Detection', icon: '🎬', color: '#c0392b' }
        };
        
        return moduleInfo[moduleName] || { 
            name: moduleName, 
            icon: '❓', 
            color: '#95a5a6' 
        };
    }
}

// Create singleton instance
const proctorService = new ProctorService();

export default proctorService;