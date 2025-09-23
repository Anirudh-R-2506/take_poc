import { app, BrowserWindow, ipcMain } from 'electron';
import path from 'node:path';
import started from 'electron-squirrel-startup';

// Import Morpheus Supervisor and Permission Manager
const ProctorSupervisor = require(path.join(__dirname, '../../morpheus/supervisor/proctorSupervisor.js'));
const PermissionManager = require(path.join(__dirname, '../../morpheus/permissions/PermissionManager.js'));

// Handle creating/removing shortcuts on Windows when installing/uninstalling.
if (started) {
  app.quit();
}

// Global variables
let mainWindow = null;
let proctorSupervisor = null;
let permissionManager = null;
let permissionService = null;

// Global error handler for EPIPE errors
process.on('uncaughtException', (error) => {
  if (error.code === 'EPIPE' || error.message.includes('EPIPE')) {
    console.warn('[Main] EPIPE error caught and ignored:', error.message);
    return; // Don't crash the app
  }

  console.error('[Main] Uncaught exception:', error);
  // Let other errors propagate normally
  throw error;
});

process.on('unhandledRejection', (reason, promise) => {
  if (reason && (reason.code === 'EPIPE' || reason.message?.includes('EPIPE'))) {
    console.warn('[Main] EPIPE rejection caught and ignored:', reason.message);
    return;
  }

  console.error('[Main] Unhandled promise rejection:', reason);
});

const createWindow = () => {
  // Create the browser window.
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 1000,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      enableRemoteModule: false
    },
  });

  // and load the index.html of the app.
  if (MAIN_WINDOW_VITE_DEV_SERVER_URL) {
    mainWindow.loadURL(MAIN_WINDOW_VITE_DEV_SERVER_URL);
  } else {
    mainWindow.loadFile(path.join(__dirname, `../renderer/${MAIN_WINDOW_VITE_NAME}/index.html`));
  }

  // Open the DevTools in development
  if (MAIN_WINDOW_VITE_DEV_SERVER_URL) {
    mainWindow.webContents.openDevTools();
  }
  
  return mainWindow;
};

// Initialize Morpheus proctoring system
const initializeMorpheus = async () => {
  console.log('[Main] Initializing Morpheus proctoring system...');

  try {
    // Use centralized permission service
    permissionService = require(path.join(__dirname, '../../morpheus/shared/PermissionService'));

    console.log('[Main] Initializing centralized permission service...');
    const permissionStatus = await permissionService.initialize();
    
    // Get the permission manager instance from service
    permissionManager = permissionService.permissionManager;
    
    if (!permissionStatus.allGranted) {
      console.warn('[Main] Not all permissions granted - workers will not start until permissions are granted');
      console.log('[Main] Missing permissions:', permissionManager.getMissingPermissions());
    }
    
    // Initialize supervisor but don't start workers yet
    proctorSupervisor = new ProctorSupervisor();
    proctorSupervisor.setMainWindow(mainWindow);
    proctorSupervisor.setPermissionManager(permissionManager);
    
    // Start supervisor - it will handle permission checking internally
    console.log('[Main] Starting supervisor (will wait for permissions)...');
    await proctorSupervisor.startAll();
    proctorSupervisor.startHealthCheck();
    
    console.log('[Main] Morpheus proctoring system initialized');
  } catch (error) {
    console.error('[Main] Failed to initialize Morpheus system:', error.message);
    // Continue with limited functionality
    proctorSupervisor = new ProctorSupervisor();
    proctorSupervisor.setMainWindow(mainWindow);
    try {
      await proctorSupervisor.startAll();
      proctorSupervisor.startHealthCheck();
    } catch (startError) {
      console.error('[Main] Failed to start supervisor:', startError);
    }
  }
};

// Setup IPC handlers for ProctorAPI
const setupIPC = () => {
  // Handle proctor commands
  ipcMain.on('proctor:command', (event, command) => {
    console.log('[Main] Received proctor command:', command);
    
    if (!proctorSupervisor) {
      console.error('[Main] ProctorSupervisor not initialized');
      return;
    }
    
    switch (command.cmd) {
      case 'restart-worker':
        if (command.payload && command.payload.moduleName) {
          proctorSupervisor.stopWorker(command.payload.moduleName);
        }
        break;
      case 'stop-worker':
        if (command.payload && command.payload.moduleName) {
          proctorSupervisor.stopWorker(command.payload.moduleName);
        }
        break;
      case 'start-all-workers':
        console.log('[Main] Starting all workers via command');
        proctorSupervisor.startAll();
        proctorSupervisor.startHealthCheck();
        break;
      default:
        console.warn('[Main] Unknown command:', command.cmd);
    }
  });
  
  // Handle async requests
  ipcMain.handle('proctor:get-status', async () => {
    if (!proctorSupervisor) return null;
    return proctorSupervisor.getWorkerStatus();
  });
  
  ipcMain.handle('proctor:restart-worker', async (event, moduleName) => {
    if (!proctorSupervisor) return false;
    proctorSupervisor.stopWorker(moduleName);
    return true;
  });
  
  ipcMain.handle('proctor:get-system-info', async () => {
    return {
      platform: process.platform,
      arch: process.arch,
      nodeVersion: process.version,
      electronVersion: process.versions.electron,
      morpheusVersion: '1.0.0'
    };
  });

  // Permission management IPC handlers
  ipcMain.handle('proctor:check-permissions', async () => {
    try {
      if (!permissionService) {
        console.warn('[Main IPC] PermissionService not initialized yet');
        return { allGranted: false, error: 'Service not initialized' };
      }
      return permissionService.getPermissionStatus();
    } catch (error) {
      console.error('[Main IPC] Error checking permissions:', error);
      return { allGranted: false, error: error.message };
    }
  });

  ipcMain.handle('proctor:request-permission', async (event, permissionType) => {
    try {
      if (!permissionService) {
        console.error('[Main IPC] PermissionService not initialized');
        return false;
      }
      
      const granted = await permissionService.requestPermission(permissionType);
      
      // Note: Workers are now started manually via startWorkers IPC call
      // This prevents automatic restarts that can cause refresh loops
      
      return granted;
    } catch (error) {
      console.error('[Main IPC] Error requesting permission:', error);
      return false;
    }
  });

  // Manual worker startup handler
  ipcMain.handle('proctor:start-workers', async () => {
    try {
      if (!proctorSupervisor) {
        console.error('[Main IPC] ProctorSupervisor not initialized');
        return false;
      }

      console.log('[Main IPC] Starting workers manually...');
      const result = await proctorSupervisor.startAll();

      if (!proctorSupervisor.healthCheckInterval) {
        proctorSupervisor.startHealthCheck();
      }

      return result;
    } catch (error) {
      console.error('[Main IPC] Error starting workers:', error);
      return false;
    }
  });

  // Note: Morpheus services are now handled via the ProctorSupervisor
  // All monitoring data comes through the worker events, not direct IPC calls

  console.log('[Main] IPC handlers setup complete');
};

// This method will be called when Electron has finished
// initialization and is ready to create browser windows.
// Some APIs can only be used after this event occurs.
app.whenReady().then(async () => {
  createWindow();
  setupIPC();

  // Initialize Morpheus after a short delay to ensure window is ready
  setTimeout(async () => {
    await initializeMorpheus();
  }, 1000);

  // On OS X it's common to re-create a window in the app when the
  // dock icon is clicked and there are no other windows open.
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

// Quit when all windows are closed, except on macOS. There, it's common
// for applications and their menu bar to stay active until the user quits
// explicitly with Cmd + Q.
app.on('window-all-closed', () => {
  // Clean up Morpheus system
  if (proctorSupervisor) {
    console.log('[Main] Shutting down Morpheus system...');
    proctorSupervisor.stopAll();
  }
  
  // Clean up Morpheus services
  try {
    const { cleanup } = require(path.join(__dirname, '../../morpheus/index'));
    cleanup();
  } catch (error) {
    console.error('[Main] Error cleaning up Morpheus services:', error.message);
  }
  
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// Handle app quit
app.on('before-quit', () => {
  if (proctorSupervisor) {
    console.log('[Main] Cleaning up Morpheus system before quit...');
    proctorSupervisor.stopAll();
  }
  
  // Clean up Morpheus services
  try {
    const { cleanup } = require(path.join(__dirname, '../../morpheus/index'));
    cleanup();
  } catch (error) {
    console.error('[Main] Error cleaning up Morpheus services:', error.message);
  }
});
