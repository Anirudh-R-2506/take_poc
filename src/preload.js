const { contextBridge, ipcRenderer } = require('electron');

// Secure API bridge for Morpheus proctoring system
contextBridge.exposeInMainWorld('proctorAPI', {
    // Subscribe to proctor events from workers
    onEvent: (callback) => {
        const wrappedCallback = (event, data) => {
            // Sanitize and validate data before passing to renderer
            if (data && typeof data === 'object' && data.module && data.payload) {
                callback({
                    module: data.module,
                    payload: data.payload,
                    timestamp: data.timestamp || Date.now()
                });
            }
        };
        
        ipcRenderer.on('proctor:event', wrappedCallback);
        
        // Return cleanup function
        return () => {
            ipcRenderer.removeListener('proctor:event', wrappedCallback);
        };
    },
    
    // Send commands to main process
    sendCommand: (command) => {
        // Validate command structure
        if (!command || typeof command !== 'object' || !command.cmd) {
            console.error('[ProctorAPI] Invalid command structure');
            return false;
        }
        
        // Whitelist allowed commands
        const allowedCommands = [
            'get-worker-status',
            'restart-worker',
            'stop-worker',
            'start-worker',
            'start-all-workers',
            'get-system-info',
            'send-worker-command'
        ];
        
        if (!allowedCommands.includes(command.cmd)) {
            console.error('[ProctorAPI] Command not allowed:', command.cmd);
            return false;
        }
        
        ipcRenderer.send('proctor:command', command);
        return true;
    },
    
    // Get worker status (returns a Promise)
    getWorkerStatus: () => {
        return ipcRenderer.invoke('proctor:get-status');
    },
    
    // Restart specific worker
    restartWorker: (moduleName) => {
        if (typeof moduleName !== 'string') {
            return Promise.reject(new Error('Module name must be a string'));
        }
        return ipcRenderer.invoke('proctor:restart-worker', moduleName);
    },
    
    // Get system information
    getSystemInfo: () => {
        return ipcRenderer.invoke('proctor:get-system-info');
    },
    
    // Subscribe to worker status updates
    onWorkerStatusChange: (callback) => {
        const wrappedCallback = (event, status) => {
            if (status && typeof status === 'object') {
                callback(status);
            }
        };
        
        ipcRenderer.on('proctor:worker-status', wrappedCallback);
        
        return () => {
            ipcRenderer.removeListener('proctor:worker-status', wrappedCallback);
        };
    },

    // Permission management APIs
    checkPermissions: () => {
        return ipcRenderer.invoke('proctor:check-permissions');
    },

    requestPermission: (permissionType) => {
        if (typeof permissionType !== 'string') {
            return Promise.reject(new Error('Permission type must be a string'));
        }
        return ipcRenderer.invoke('proctor:request-permission', permissionType);
    },

    startWorkers: () => {
        return ipcRenderer.invoke('proctor:start-workers');
    },

    stopWorkers: () => {
        return ipcRenderer.invoke('proctor:stop-workers');
    },

    // Send command to specific worker
    sendWorkerCommand: (workerName, command) => {
        if (typeof workerName !== 'string' || !command || typeof command !== 'object') {
            return Promise.reject(new Error('Invalid worker command parameters'));
        }
        return ipcRenderer.invoke('proctor:send-worker-command', { workerName, command });
    }
});

// Note: Direct Morpheus services API removed
// All monitoring data now comes through ProctorAPI events via the supervisor

// Log that preload script has loaded
console.log('[Preload] Morpheus ProctorAPI bridge initialized');
console.log('[Preload] Morpheus services API exposed');
