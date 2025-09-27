/**
 * Exam Control API - Ready-to-use functions for your exam application
 *
 * This module provides all the functions you need for:
 * 1. Pre-assessment permission checking
 * 2. Starting exam monitoring
 * 3. Integrating violation data from all workers
 * 4. Stopping exam monitoring
 */

import proctorService from './proctorService';

class ExamControlAPI {
    constructor() {
        this.isMonitoring = false;
        this.eventUnsubscribe = null;
        this.statusUnsubscribe = null;
        this.violationCallbacks = new Set();
    }

    // ===== PRE-ASSESSMENT FUNCTIONS =====

    /**
     * Check all required permissions for exam
     * @returns {Promise<Object>} Permission status object
     */
    async checkPermissions() {
        try {
            const status = await window.proctorAPI.checkPermissions();
            return status;
        } catch (error) {
            console.error('[ExamAPI] Failed to check permissions:', error);
            return null;
        }
    }

    /**
     * Request a specific permission
     * @param {string} permissionType - Type of permission to request
     * @returns {Promise<boolean>} Success status
     */
    async requestPermission(permissionType) {
        try {
            const result = await window.proctorAPI.requestPermission(permissionType);
            return result;
        } catch (error) {
            console.error(`[ExamAPI] Failed to request permission ${permissionType}:`, error);
            return false;
        }
    }

    /**
     * Check if all permissions are granted and ready for exam
     * @returns {Promise<boolean>} True if ready to start exam
     */
    async isReadyForExam() {
        const status = await this.checkPermissions();
        return status?.allGranted === true;
    }

    /**
     * Get list of missing permissions
     * @returns {Promise<Array>} Array of missing permission objects
     */
    async getMissingPermissions() {
        const status = await this.checkPermissions();
        if (!status?.permissions) return [];

        return Object.entries(status.permissions)
            .filter(([_, permission]) => permission.required && permission.status !== 'granted')
            .map(([key, permission]) => ({
                key,
                name: permission.name,
                description: permission.description,
                status: permission.status
            }));
    }

    // ===== EXAM MONITORING FUNCTIONS =====

    /**
     * Start exam monitoring - starts all workers
     * @returns {Promise<boolean>} Success status
     */
    async startExamMonitoring() {
        try {
            if (this.isMonitoring) {
                console.warn('[ExamAPI] Monitoring already started');
                return true;
            }

            // Check permissions first
            const isReady = await this.isReadyForExam();
            if (!isReady) {
                console.error('[ExamAPI] Cannot start monitoring - permissions not granted');
                return false;
            }

            // Start all workers
            const result = await window.proctorAPI.startWorkers();
            if (!result) {
                console.error('[ExamAPI] Failed to start workers');
                return false;
            }

            // Setup event listeners
            this.setupEventListeners();
            this.isMonitoring = true;

            console.log('[ExamAPI] Exam monitoring started successfully');
            return true;
        } catch (error) {
            console.error('[ExamAPI] Failed to start exam monitoring:', error);
            return false;
        }
    }

    /**
     * Stop exam monitoring - stops all workers
     * @returns {Promise<boolean>} Success status
     */
    async stopExamMonitoring() {
        try {
            if (!this.isMonitoring) {
                console.warn('[ExamAPI] Monitoring not active');
                return true;
            }

            // Stop all workers
            const result = await window.proctorAPI.stopWorkers();
            if (!result) {
                console.error('[ExamAPI] Failed to stop workers');
                return false;
            }

            // Cleanup event listeners
            this.cleanupEventListeners();
            this.isMonitoring = false;

            console.log('[ExamAPI] Exam monitoring stopped successfully');
            return true;
        } catch (error) {
            console.error('[ExamAPI] Failed to stop exam monitoring:', error);
            return false;
        }
    }

    /**
     * Register callback for violation events from ANY worker
     * @param {Function} callback - Function to call when violations occur
     * @returns {Function} Unsubscribe function
     */
    onViolation(callback) {
        this.violationCallbacks.add(callback);

        return () => {
            this.violationCallbacks.delete(callback);
        };
    }

    /**
     * Get current monitoring status
     * @returns {boolean} True if monitoring is active
     */
    isMonitoringActive() {
        return this.isMonitoring;
    }

    // ===== INTERNAL METHODS =====

    setupEventListeners() {
        // Subscribe to proctor events from ALL workers
        this.eventUnsubscribe = proctorService.onEvent((module, payload, timestamp) => {
            // This receives data from ALL workers in one place
            const violationData = {
                module,
                payload,
                timestamp,
                // Add convenience properties
                isViolation: this.isViolationEvent(module, payload),
                threatLevel: this.getThreatLevel(module, payload),
                description: this.getViolationDescription(module, payload)
            };

            // Notify all registered callbacks
            this.violationCallbacks.forEach(callback => {
                try {
                    callback(violationData);
                } catch (error) {
                    console.error('[ExamAPI] Error in violation callback:', error);
                }
            });
        });

        // Subscribe to worker status changes
        this.statusUnsubscribe = proctorService.onStatusChange((status) => {
            console.log('[ExamAPI] Worker status update:', status);
        });
    }

    cleanupEventListeners() {
        if (this.eventUnsubscribe) {
            this.eventUnsubscribe();
            this.eventUnsubscribe = null;
        }
        if (this.statusUnsubscribe) {
            this.statusUnsubscribe();
            this.statusUnsubscribe = null;
        }
    }

    /**
     * Determine if event represents a violation
     */
    isViolationEvent(module, payload) {
        if (!payload) return false;

        // Check for explicit violations array
        if (payload.violations && payload.violations.length > 0) return true;

        // Module-specific violation detection
        switch (module) {
            case 'process-watch':
                return payload.blacklisted_found ||
                       (payload.max_threat_level && payload.max_threat_level !== 'NONE');

            case 'screen-watch':
                return payload.isScreenCaptured ||
                       (payload.total_sessions && payload.total_sessions > 0);

            case 'vm-detect':
                return payload.isInsideVM;

            case 'clipboard-worker':
                return payload.eventType === 'clipboard-changed';

            case 'focus-idle-watch':
                return payload.eventType === 'focus-lost' || payload.eventType === 'idle-start';

            case 'notification-blocker':
                return payload.eventType === 'violation';

            case 'device-watch':
                return payload.violations && payload.violations.length > 0;

            default:
                return false;
        }
    }

    /**
     * Get threat level from payload
     */
    getThreatLevel(module, payload) {
        if (!payload) return 'low';

        // Check for explicit threat level
        if (payload.max_threat_level) {
            return payload.max_threat_level.toLowerCase();
        }

        // Check violations array
        if (payload.violations && payload.violations.length > 0) {
            const maxSeverity = Math.max(...payload.violations.map(v => v.severity || 1));
            switch (maxSeverity) {
                case 4: return 'critical';
                case 3: return 'high';
                case 2: return 'medium';
                default: return 'low';
            }
        }

        // Module-specific threat assessment
        switch (module) {
            case 'process-watch':
                return payload.blacklisted_found ? 'critical' : 'low';
            case 'screen-watch':
                return payload.isScreenCaptured ? 'critical' : 'low';
            case 'vm-detect':
                return payload.isInsideVM ? 'critical' : 'low';
            default:
                return 'low';
        }
    }

    /**
     * Get human-readable violation description
     */
    getViolationDescription(module, payload) {
        if (!this.isViolationEvent(module, payload)) {
            return 'No violation detected';
        }

        switch (module) {
            case 'process-watch':
                if (payload.blacklisted_found) return 'Blacklisted process detected';
                if (payload.violations) return `${payload.violations.length} process violation(s)`;
                return 'Process violation detected';

            case 'screen-watch':
                if (payload.isScreenCaptured) return 'Screen sharing/recording detected';
                return 'Screen violation detected';

            case 'vm-detect':
                return `Virtual machine detected: ${payload.detectedVM || 'Unknown'}`;

            case 'clipboard-worker':
                return 'Clipboard content changed';

            case 'focus-idle-watch':
                return payload.eventType === 'focus-lost' ? 'Window focus lost' : 'User idle detected';

            case 'notification-blocker':
                return 'Notification settings violated';

            case 'device-watch':
                return `${payload.violations?.length || 0} device violation(s)`;

            default:
                return 'Violation detected';
        }
    }
}

// Export singleton instance
const examAPI = new ExamControlAPI();
export default examAPI;