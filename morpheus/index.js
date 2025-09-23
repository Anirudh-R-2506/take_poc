const sudoManager = require('./sudoManager');

class MorpheusServices {
    constructor() {
        this.sudoManager = sudoManager;
        this.initialized = false;
    }

    /**
     * Initialize services and request necessary permissions
     * @returns {Promise<boolean>} - Whether initialization was successful
     */
    async initialize() {
        try {
            console.log('[Morpheus] Initializing sudo permissions...');
            
            // Initialize sudo permissions for services that need it
            await this.sudoManager.initializePermissions();
            
            this.initialized = true;
            console.log('[Morpheus] Permissions initialized successfully');
            return true;
        } catch (error) {
            console.error('[Morpheus] Failed to initialize permissions:', error.message);
            this.initialized = false;
            return false;
        }
    }

    /**
     * Check if services are initialized
     * @returns {boolean}
     */
    isInitialized() {
        return this.initialized;
    }

    /**
     * Cleanup and revoke permissions
     */
    cleanup() {
        console.log('[Morpheus] Cleaning up permissions...');
        this.sudoManager.revokeSudo();
        this.initialized = false;
    }
}

// Export singleton instance
const morpheus = new MorpheusServices();

module.exports = {
    // Main services object
    morpheus,
    
    // Individual service access  
    sudoManager: morpheus.sudoManager,
    
    // Convenience methods
    async init() {
        return await morpheus.initialize();
    },
    
    cleanup() {
        return morpheus.cleanup();
    }
};