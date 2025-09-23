const { fork } = require("child_process");
const path = require("path");
const EventEmitter = require("events");
const permissionService = require("../shared/PermissionService");

class ProctorSupervisor extends EventEmitter {
  constructor() {
    super();
    this.workers = new Map();
    this.mainWindow = null;
    this.permissionManager = null;
    this.restartDelay = 2000; // 2 seconds

    // Define all worker modules
    this.workerModules = [
      "process-watch-worker",
      "device-watch-worker", // External device monitoring
      "bt-watch-worker",
      "screen-watch-worker", // Includes recording/overlay detection
      "notification-watch-worker",
      "vm-detect-worker",
      "clipboard-worker",
      "focus-idle-watch-worker",
    ];

    console.log(
      "[ProctorSupervisor] Initialized with",
      this.workerModules.length,
      "worker modules"
    );
  }

  setMainWindow(mainWindow) {
    this.mainWindow = mainWindow;
    console.log("[ProctorSupervisor] Main window set");
  }

  setPermissionManager(permissionManager) {
    this.permissionManager = permissionManager;
    console.log("[ProctorSupervisor] Permission manager set");
  }

  async startAll() {
    console.log("[ProctorSupervisor] 🚀 Starting all workers...");

    try {
      // Wait for permissions to be ready
      console.log("[ProctorSupervisor] Waiting for permissions...");
      const permissionStatus = await permissionService.waitForPermissions();
      
      if (!permissionStatus.allGranted) {
        console.warn("[ProctorSupervisor] ⚠️ Not all permissions granted - workers will not start");
        console.log("[ProctorSupervisor] Permission status:", permissionStatus);
        return false;
      }
      
      console.log("[ProctorSupervisor] ✅ All permissions granted, starting workers...");
    } catch (error) {
      console.error("[ProctorSupervisor] Failed to get permissions:", error);
      return false;
    }

    console.log("[ProctorSupervisor] Worker modules to start:", this.workerModules);

    for (const moduleName of this.workerModules) {
      console.log(`[ProctorSupervisor] 📋 Queuing worker: ${moduleName}`);
      this.startWorker(moduleName);
    }

    console.log("[ProctorSupervisor] ✅ All workers startup initiated");
    
    // Log status after a delay
    setTimeout(() => {
      console.log("[ProctorSupervisor] 📊 Worker status after 5 seconds:");
      const status = this.getWorkerStatus();
      for (const [name, info] of Object.entries(status)) {
        console.log(`[ProctorSupervisor]   ${name}: ${info.running ? '✅ Running' : '❌ Not running'} ${info.pid ? `(PID: ${info.pid})` : ''}`);
      }
    }, 5000);
  }

  startWorker(moduleName) {
    if (this.workers.has(moduleName)) {
      console.log(`[ProctorSupervisor] Worker ${moduleName} already running`);
      return;
    }

    const workerPath = path.join(__dirname, "../workers", `${moduleName}.js`);
    console.log(`[ProctorSupervisor] 🚀 Starting worker: ${moduleName} at ${workerPath}`);

    try {
      const worker = fork(workerPath, {
        stdio: ["pipe", "pipe", "pipe", "ipc"],
        silent: false,
      });

      // Handle EPIPE errors on worker stdio
      if (worker.stdout) {
        worker.stdout.on('error', (error) => {
          if (error.code === 'EPIPE') {
            console.warn(`[ProctorSupervisor] EPIPE on ${moduleName} stdout, ignoring`);
          } else {
            console.error(`[ProctorSupervisor] ${moduleName} stdout error:`, error);
          }
        });
      }

      if (worker.stderr) {
        worker.stderr.on('error', (error) => {
          if (error.code === 'EPIPE') {
            console.warn(`[ProctorSupervisor] EPIPE on ${moduleName} stderr, ignoring`);
          } else {
            console.error(`[ProctorSupervisor] ${moduleName} stderr error:`, error);
          }
        });
      }

      const workerInfo = {
        process: worker,
        module: moduleName,
        startTime: Date.now(),
        restartCount: 0,
        lastHeartbeat: Date.now(),
      };

      this.workers.set(moduleName, workerInfo);

      // Handle worker messages
      worker.on("message", (message) => {
        this.handleWorkerMessage(moduleName, message);
      });

      // Handle worker exit
      worker.on("exit", (code, signal) => {
        this.handleWorkerExit(moduleName, code, signal);
      });

      // Handle worker error
      worker.on("error", (error) => {
        console.error(`[ProctorSupervisor] ❌ Worker ${moduleName} error:`, error);
        this.handleWorkerExit(moduleName, -1, "ERROR");
      });

      // Log stdout/stderr from worker
      worker.stdout.on('data', (data) => {
        console.log(`[ProctorSupervisor] [${moduleName}] STDOUT:`, data.toString().trim());
      });

      worker.stderr.on('data', (data) => {
        console.error(`[ProctorSupervisor] [${moduleName}] STDERR:`, data.toString().trim());
      });

      console.log(
        `[ProctorSupervisor] ✅ Worker ${moduleName} started with PID ${worker.pid}`
      );
      
      // Send initial command to verify worker is responsive
      setTimeout(() => {
        if (this.workers.has(moduleName)) {
          console.log(`[ProctorSupervisor] 📡 Sending ping to ${moduleName}`);
          worker.send({ cmd: "ping", timestamp: Date.now() });
        }
      }, 1000);
      
    } catch (error) {
      console.error(
        `[ProctorSupervisor] ❌ Failed to start worker ${moduleName}:`,
        error
      );
      // Schedule restart
      setTimeout(() => {
        this.startWorker(moduleName);
      }, this.restartDelay);
    }
  }

  handleWorkerMessage(moduleName, message) {
    if (!message || typeof message !== "object") {
      console.warn(`[ProctorSupervisor] Invalid message from ${moduleName}:`, message);
      return;
    }

    const workerInfo = this.workers.get(moduleName);
    if (!workerInfo) {
      console.warn(`[ProctorSupervisor] Message from unknown worker ${moduleName}:`, message);
      return;
    }

    console.log(`[ProctorSupervisor] Message from ${moduleName}:`, JSON.stringify(message, null, 2));

    switch (message.type) {
      case "heartbeat":
        workerInfo.lastHeartbeat = Date.now();
        console.log(
          `[ProctorSupervisor] ✓ Heartbeat from ${moduleName} (PID: ${message.pid})`
        );
        break;

      case "proctor-event":
        console.log(`[ProctorSupervisor] ⚡ Proctor event from ${moduleName}:`, {
          module: message.module || moduleName,
          payload: message.payload
        });
        
        // Forward proctor events to renderer process
        if (this.mainWindow && this.mainWindow.webContents) {
          this.mainWindow.webContents.send("proctor:event", {
            module: message.module || moduleName,
            payload: message.payload,
            timestamp: Date.now(),
          });
          console.log(`[ProctorSupervisor] ✓ Forwarded event from ${moduleName} to renderer`);
        } else {
          console.error(`[ProctorSupervisor] ✗ Cannot forward event from ${moduleName}: mainWindow not available`);
        }
        break;

      default:
        console.warn(
          `[ProctorSupervisor] ⚠ Unknown message type '${message.type}' from ${moduleName}:`,
          message
        );
    }
  }

  handleWorkerExit(moduleName, code, signal) {
    console.log(
      `[ProctorSupervisor] Worker ${moduleName} exited with code ${code}, signal ${signal}`
    );

    const workerInfo = this.workers.get(moduleName);
    if (workerInfo) {
      workerInfo.restartCount++;
      console.log(
        `[ProctorSupervisor] Worker ${moduleName} restart count: ${workerInfo.restartCount}`
      );
    }

    // Remove from active workers
    this.workers.delete(moduleName);

    // Schedule restart with backoff
    const delay =
      this.restartDelay *
      (workerInfo ? Math.min(workerInfo.restartCount, 5) : 1);
    console.log(`[ProctorSupervisor] Restarting ${moduleName} in ${delay}ms`);

    setTimeout(() => {
      this.startWorker(moduleName);
    }, delay);
  }

  stopWorker(moduleName) {
    const workerInfo = this.workers.get(moduleName);
    if (!workerInfo) {
      console.log(`[ProctorSupervisor] Worker ${moduleName} not running`);
      return;
    }

    console.log(`[ProctorSupervisor] Stopping worker ${moduleName}`);

    // Send stop command
    workerInfo.process.send({ cmd: "stop" });

    // Force kill after timeout
    setTimeout(() => {
      if (this.workers.has(moduleName)) {
        console.log(`[ProctorSupervisor] Force killing worker ${moduleName}`);
        workerInfo.process.kill("SIGKILL");
      }
    }, 5000);

    this.workers.delete(moduleName);
  }

  stopAll() {
    console.log("[ProctorSupervisor] Stopping all workers...");

    for (const moduleName of this.workers.keys()) {
      this.stopWorker(moduleName);
    }

    console.log("[ProctorSupervisor] All workers stopped");
  }

  getWorkerStatus() {
    const status = {};

    for (const [moduleName, workerInfo] of this.workers.entries()) {
      status[moduleName] = {
        running: true,
        pid: workerInfo.process.pid,
        startTime: workerInfo.startTime,
        restartCount: workerInfo.restartCount,
        lastHeartbeat: workerInfo.lastHeartbeat,
        uptime: Date.now() - workerInfo.startTime,
      };
    }

    // Check for missing workers
    for (const moduleName of this.workerModules) {
      if (!status[moduleName]) {
        status[moduleName] = {
          running: false,
          restartScheduled: true,
        };
      }
    }

    return status;
  }

  // Monitor worker health
  startHealthCheck() {
    setInterval(() => {
      const now = Date.now();
      const staleThreshold = 30000; // 30 seconds

      for (const [moduleName, workerInfo] of this.workers.entries()) {
        if (now - workerInfo.lastHeartbeat > staleThreshold) {
          console.warn(
            `[ProctorSupervisor] Worker ${moduleName} appears stale, restarting...`
          );
          this.stopWorker(moduleName);
        }
      }
    }, 15000); // Check every 15 seconds
  }

  // Send command to specific worker
  sendCommand(moduleName, command) {
    const workerInfo = this.workers.get(moduleName);
    if (!workerInfo) {
      console.error(
        `[ProctorSupervisor] Cannot send command to ${moduleName}: worker not found`
      );
      return false;
    }

    workerInfo.process.send(command);
    return true;
  }

  // Send command to all workers
  broadcastCommand(command) {
    for (const [moduleName, workerInfo] of this.workers.entries()) {
      workerInfo.process.send(command);
    }
  }
}

module.exports = ProctorSupervisor;
