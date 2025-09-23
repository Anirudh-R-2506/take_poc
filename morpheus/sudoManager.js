// Use alternative sudo approach since electron-sudo has compatibility issues
const { execSync, spawn } = require('child_process');
const { promisify } = require('util');

class SudoManager {
    constructor() {
        this.sudoOptions = {
            name: 'Morpheus Proctoring System',
            icns: '/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/ExecutableBinaryIcon.icns', // macOS
        };
        this.isSudoActive = false;
        this.sudoProcesses = new Map();
    }

    /**
     * Request sudo privileges for the application
     * @param {string} reason - Reason for requesting sudo
     * @returns {Promise<boolean>} - Whether sudo was granted
     */
    async requestSudo(reason = 'System monitoring requires elevated privileges') {
        try {
            console.log(`[SudoManager] Requesting sudo: ${reason}`);
            
            // Test sudo with a simple command
            const result = await this.executeSudoCommand(['echo', 'sudo_test'], {
                name: this.sudoOptions.name + ' - ' + reason
            });
            
            if (result.includes('sudo_test')) {
                this.isSudoActive = true;
                console.log('[SudoManager] Sudo privileges granted');
                return true;
            }
            
            return false;
        } catch (error) {
            console.error('[SudoManager] Failed to get sudo privileges:', error.message);
            this.isSudoActive = false;
            return false;
        }
    }

    /**
     * Execute a command with sudo privileges using osascript for macOS GUI sudo
     * @param {string[]} command - Command and arguments array
     * @param {object} options - Additional sudo options
     * @returns {Promise<string>} - Command output
     */
    async executeSudoCommand(command, options = {}) {
        return new Promise((resolve, reject) => {
            try {
                if (process.platform === 'darwin') {
                    // Use osascript for macOS GUI sudo prompt
                    const scriptName = options.name || this.sudoOptions.name;
                    const fullCommand = command.join(' ');
                    
                    // Escape the command for AppleScript
                    const escapedCommand = fullCommand.replace(/"/g, '\\"');
                    
                    const osascript = `do shell script "${escapedCommand}" with administrator privileges with prompt "${scriptName} requires administrator privileges:"`;
                    
                    const result = execSync(`osascript -e '${osascript}'`, { 
                        encoding: 'utf8',
                        timeout: 30000 
                    });
                    
                    resolve(result.trim());
                } else if (process.platform === 'win32') {
                    // For Windows, use PowerShell with UAC elevation
                    const scriptName = options.name || this.sudoOptions.name;
                    const fullCommand = command.join(' ');
                    
                    // Use PowerShell Start-Process with -Verb RunAs for UAC elevation
                    const powershellCommand = `Start-Process -FilePath "${command[0]}" -ArgumentList "${command.slice(1).join('", "')}" -Verb RunAs -WindowStyle Hidden -Wait`;
                    const result = execSync(`powershell -Command "${powershellCommand}"`, { 
                        encoding: 'utf8',
                        timeout: 30000 
                    });
                    
                    resolve(result.trim());
                } else {
                    // For Linux/other platforms, use regular sudo (will prompt in terminal)
                    const result = execSync(`sudo ${command.join(' ')}`, { 
                        encoding: 'utf8',
                        timeout: 30000 
                    });
                    resolve(result.trim());
                }
            } catch (error) {
                reject(new Error(`Sudo command failed: ${error.message}`));
            }
        });
    }

    /**
     * Execute a command with optional sudo based on service requirements
     * @param {string[]} command - Command and arguments array
     * @param {boolean} requiresSudo - Whether the command needs sudo
     * @param {string} serviceName - Name of the service requesting execution
     * @returns {Promise<string>} - Command output
     */
    async executeCommand(command, requiresSudo = false, serviceName = 'unknown') {
        try {
            if (requiresSudo) {
                // Ensure we have sudo privileges
                if (!this.isSudoActive) {
                    const sudoGranted = await this.requestSudo(`${serviceName} monitoring`);
                    if (!sudoGranted) {
                        throw new Error(`Sudo privileges required for ${serviceName} but not granted`);
                    }
                }

                return await this.executeSudoCommand(command, {
                    name: `${this.sudoOptions.name} - ${serviceName}`
                });
            } else {
                // Execute without sudo
                const { spawn } = require('child_process');
                
                return new Promise((resolve, reject) => {
                    const process = spawn(command[0], command.slice(1), {
                        stdio: ['pipe', 'pipe', 'pipe']
                    });

                    let stdout = '';
                    let stderr = '';

                    process.stdout.on('data', (data) => {
                        stdout += data.toString();
                    });

                    process.stderr.on('data', (data) => {
                        stderr += data.toString();
                    });

                    process.on('close', (code) => {
                        if (code === 0) {
                            resolve(stdout.trim());
                        } else {
                            reject(new Error(`Command failed with code ${code}: ${stderr}`));
                        }
                    });

                    process.on('error', (error) => {
                        reject(new Error(`Command execution error: ${error.message}`));
                    });

                    // Set timeout
                    setTimeout(() => {
                        process.kill();
                        reject(new Error('Command timeout'));
                    }, 15000);
                });
            }
        } catch (error) {
            console.error(`[SudoManager] Command execution failed for ${serviceName}:`, error.message);
            throw error;
        }
    }

    /**
     * Check if sudo privileges are currently active
     * @returns {boolean}
     */
    isSudoGranted() {
        return this.isSudoActive;
    }

    /**
     * Check if the current process has administrator/elevated privileges
     * @returns {Promise<boolean>} - Whether the current process is elevated
     */
    async checkCurrentPrivileges() {
        try {
            if (process.platform === 'darwin') {
                // On macOS, check if we can access a root-only resource
                const result = execSync('id -u', { encoding: 'utf8', timeout: 5000 });
                const uid = parseInt(result.trim());
                return uid === 0; // root user
            } else if (process.platform === 'win32') {
                // On Windows, use NET SESSION command which only succeeds with admin privileges
                const result = execSync('net session', { encoding: 'utf8', timeout: 5000, stdio: 'pipe' });
                // If we get here without error, we have admin privileges
                return true;
            } else {
                // On Linux, check if we're root
                const result = execSync('id -u', { encoding: 'utf8', timeout: 5000 });
                const uid = parseInt(result.trim());
                return uid === 0; // root user
            }
        } catch (error) {
            // If the command fails, we likely don't have elevated privileges
            console.log('[SudoManager] Current privileges check result: not elevated');
            return false;
        }
    }

    /**
     * Request administrator privileges using platform-specific methods
     * @param {string} reason - Reason for requesting privileges
     * @returns {Promise<boolean>} - Whether privileges were granted
     */
    async requestAdministratorPrivileges(reason = 'System monitoring requires elevated privileges') {
        try {
            console.log(`[SudoManager] Requesting administrator privileges: ${reason}`);
            
            // First check if we already have privileges
            const alreadyElevated = await this.checkCurrentPrivileges();
            if (alreadyElevated) {
                console.log('[SudoManager] Already running with elevated privileges');
                this.isSudoActive = true;
                return true;
            }
            
            if (process.platform === 'win32') {
                // On Windows, we can't elevate the current process, but we can test elevation capabilities
                // Show a message that the app needs to be run as Administrator
                console.log('[SudoManager] Windows: Application needs to be run as Administrator for full functionality');
                console.log('[SudoManager] Please restart the application by right-clicking and selecting "Run as Administrator"');
                return false;
            } else {
                // On macOS/Linux, attempt to get sudo privileges
                return await this.requestSudo(reason);
            }
        } catch (error) {
            console.error('[SudoManager] Failed to request administrator privileges:', error.message);
            return false;
        }
    }

    /**
     * Revoke sudo privileges (for cleanup)
     */
    revokeSudo() {
        this.isSudoActive = false;
        console.log('[SudoManager] Sudo privileges revoked');
    }

    /**
     * Get a list of services that require sudo
     * @returns {object} - Service requirements
     */
    getServiceRequirements() {
        if (process.platform === 'darwin') {
            return {
                'accessibility-services': true,  // Combined accessibility request for all macOS services
                'process-watch': false,  // Process listing doesn't need sudo
                'device-watch': false,  // Basic device enumeration doesn't need sudo
                'vm-detect': false,  // VM detection using standard APIs doesn't need sudo
                'bluetooth': false,  // system_profiler doesn't need sudo
            };
        } else {
            return {
                'screen-watch': true,  // Windows screen capture may need elevated permissions
                'clipboard-watch': false,  // Windows clipboard API doesn't need elevation
                'focus-idle-watch': false,  // Windows focus detection doesn't need elevation
                'notification-watch': false,  // Windows notification API doesn't need elevation
                'process-watch': false,  // Process listing doesn't need sudo
                'device-watch': false,  // Basic device enumeration doesn't need sudo
                'vm-detect': false,  // VM detection using standard APIs doesn't need sudo
                'bluetooth': false,  // Windows Bluetooth API doesn't need elevation
            };
        }
    }

    /**
     * Request accessibility permissions on macOS
     * @returns {Promise<boolean>} - Whether permissions were granted
     */
    async requestAccessibilityPermissions() {
        if (process.platform !== 'darwin') {
            return true; // Not needed on other platforms
        }

        try {
            console.log('[SudoManager] Requesting accessibility permissions for macOS...');
            
            // Use a simple AppleScript to trigger accessibility permission request
            const result = execSync(`osascript -e 'tell application "System Events" to return name of every process'`, { 
                encoding: 'utf8',
                timeout: 10000 
            });
            
            if (result && result.trim().length > 0) {
                console.log('[SudoManager] Accessibility permissions granted');
                return true;
            }
            
            return false;
        } catch (error) {
            console.warn('[SudoManager] Accessibility permissions may not be granted:', error.message);
            return false;
        }
    }

    /**
     * Pre-request sudo and accessibility permissions for all services that need it
     * @returns {Promise<boolean>} - Whether all required permissions were granted
     */
    async initializePermissions() {
        try {
            const requirements = this.getServiceRequirements();
            const servicesNeedingSudo = Object.entries(requirements)
                .filter(([service, needsSudo]) => needsSudo)
                .map(([service]) => service);

            if (servicesNeedingSudo.length === 0) {
                console.log('[SudoManager] No services require elevated privileges');
                return true;
            }

            console.log(`[SudoManager] Services requiring elevated privileges: ${servicesNeedingSudo.join(', ')}`);
            
            if (process.platform === 'darwin') {
                // On macOS, request accessibility permissions (which includes screen recording, etc.)
                console.log('[SudoManager] Requesting accessibility permissions for macOS monitoring services...');
                const accessibilityGranted = await this.requestAccessibilityPermissions();
                if (!accessibilityGranted) {
                    console.warn('[SudoManager] Accessibility permissions not granted - some monitoring services may be limited');
                }
                return accessibilityGranted;
            } else {
                // On other platforms, request sudo
                const sudoGranted = await this.requestSudo(
                    `Multiple monitoring services (${servicesNeedingSudo.join(', ')}) require elevated privileges`
                );

                if (!sudoGranted) {
                    console.warn('[SudoManager] Sudo not granted - some services may have limited functionality');
                    return false;
                }

                return sudoGranted;
            }
        } catch (error) {
            console.error('[SudoManager] Failed to initialize permissions:', error.message);
            return false;
        }
    }
}

// Singleton instance
const sudoManager = new SudoManager();

module.exports = sudoManager;