import React, { useState, useEffect, useCallback, useRef } from "react";
import proctorService from "./proctorService";
import PermissionStatusBadges from "./components/PermissionStatusBadges";
import "./ProctorDashboard.css";

const ProctorDashboard = () => {
  // Refs to prevent re-render loops
  const isInitialized = useRef(false);
  const eventUnsubscribe = useRef(null);
  const statusUnsubscribe = useRef(null);
  const hasCheckedInitialPermissions = useRef(false);

  // Core app state
  const [isConnected, setIsConnected] = useState(false);
  const [appState, setAppState] = useState('initial'); // 'initial' | 'permissions' | 'dashboard'

  // Permission state
  const [permissionStatus, setPermissionStatus] = useState(null);
  const [isCheckingPermissions, setIsCheckingPermissions] = useState(false);

  // Dashboard state
  const [moduleData, setModuleData] = useState({});
  const [workerStatus, setWorkerStatus] = useState({});
  const [lastUpdate, setLastUpdate] = useState(null);

  // Manual permission check function (for refresh button)
  const checkPermissions = useCallback(async () => {
    if (isCheckingPermissions) {
      console.log("[ProctorDashboard] Permission check already in progress");
      return;
    }

    setIsCheckingPermissions(true);
    console.log("[ProctorDashboard] Checking permissions...");

    try {
      if (window.proctorAPI && window.proctorAPI.checkPermissions) {
        const status = await window.proctorAPI.checkPermissions();
        console.log("[ProctorDashboard] Permission status received:", status);

        setPermissionStatus(status);

        // Debug permission status
        console.log("[ProctorDashboard] Permission status details:", {
          status,
          allGranted: status?.allGranted,
          permissions: status?.permissions
        });

        // If all permissions are granted after manual retry, start workers and proceed
        if (status && status.allGranted) {
          console.log("[ProctorDashboard] All permissions granted after manual check! Starting workers and proceeding to dashboard...");

          try {
            if (window.proctorAPI.startWorkers) {
              console.log("[ProctorDashboard] Calling startWorkers...");
              const result = await window.proctorAPI.startWorkers();
              console.log("[ProctorDashboard] startWorkers result:", result);

              console.log("[ProctorDashboard] Workers started, switching to dashboard");
              setAppState('dashboard');
            } else {
              console.warn("[ProctorDashboard] startWorkers not available, switching to dashboard anyway");
              setAppState('dashboard');
            }
          } catch (workerError) {
            console.error("[ProctorDashboard] Error starting workers:", workerError);
            // Still switch to dashboard even if there's an error
            console.log("[ProctorDashboard] Switching to dashboard despite worker error");
            setAppState('dashboard');
          }
        } else {
          console.log("[ProctorDashboard] Missing permissions - staying on permission view:", status?.permissions ?
            Object.entries(status.permissions).filter(([_, perm]) => perm.required && perm.status !== 'granted') :
            'Unknown');
          setAppState('permissions');
        }
      } else {
        console.error("[ProctorDashboard] ProctorAPI checkPermissions not available");
      }
    } catch (error) {
      console.error("[ProctorDashboard] Error checking permissions:", error);
    } finally {
      setIsCheckingPermissions(false);
    }
  }, [isCheckingPermissions]);

  // Request specific permission
  const handleRequestPermission = useCallback(async (permissionType) => {
    try {
      console.log(`[ProctorDashboard] Requesting permission: ${permissionType}`);

      if (window.proctorAPI && window.proctorAPI.requestPermission) {
        await window.proctorAPI.requestPermission(permissionType);
        console.log(`[ProctorDashboard] Permission ${permissionType} requested - please grant and refresh`);
      }
    } catch (error) {
      console.error(`[ProctorDashboard] Error requesting ${permissionType} permission:`, error);
    }
  }, []);

  // Restart worker function
  const handleRestartWorker = useCallback(async (moduleName) => {
    try {
      const success = await proctorService.restartWorker(moduleName);
      if (success) {
        console.log(`[ProctorDashboard] Restarted worker: ${moduleName}`);
      }
    } catch (error) {
      console.error(`[ProctorDashboard] Error restarting worker ${moduleName}:`, error);
    }
  }, []);

  // Reset notification blocker to original state
  const handleResetNotificationBlocker = useCallback(async () => {
    try {
      console.log(`[ProctorDashboard] Resetting notification blocker to original state...`);

      // Send reset command to the notification-blocker worker
      if (window.proctorAPI && window.proctorAPI.sendWorkerCommand) {
        const success = await window.proctorAPI.sendWorkerCommand('notification-blocker-worker', {
          cmd: 'resetToOriginal',
          timestamp: Date.now()
        });

        if (success) {
          console.log(`[ProctorDashboard] Reset command sent to notification blocker worker`);
        } else {
          console.error(`[ProctorDashboard] Failed to send reset command to notification blocker worker`);
        }
      } else {
        console.error(`[ProctorDashboard] ProctorAPI not available for worker communication`);
      }
    } catch (error) {
      console.error(`[ProctorDashboard] Error resetting notification blocker:`, error);
    }
  }, []);

  // Utility functions
  const formatTimestamp = useCallback((timestamp) => {
    if (!timestamp) return "Never";
    return new Date(timestamp).toLocaleTimeString();
  }, []);

  const getThreatLevel = useCallback((data) => {
    if (!data) return "unknown";

    // High threat indicators
    if (data.blacklisted_found === true) return "high";
    if (data.matches && data.matches.length > 0) return "high";
    if (data.isInsideVM === true) return "high";
    if (data.eventType === "notification-arrived") return "high";
    if (data.eventType === "clipboard-changed") return "high";
    if (data.eventType === "focus-lost") return "high";
    if (data.eventType === "violation") return "high";
    if (data.userModified === true) return "high";
    if (data.recordingProcesses && data.recordingProcesses.length > 0) return "high";

    // Medium threat indicators
    if (data.mirroring === true) return "normal";
    if (data.externalDisplays && data.externalDisplays.length > 0) return "normal";
    if (data.inputDevices && data.inputDevices.length > 2) return "normal";

    // Normal/good indicators
    if (data.eventType === "focus-gained") return "normal";
    if (data.eventType === "heartbeat") return "low";

    return "low";
  }, []);

  const getThreatLevelColor = useCallback((level) => {
    switch (level) {
      case "high": return "#e74c3c";
      case "normal": return "#27ae60";
      case "low": return "#95a5a6";
      default: return "#f39c12";
    }
  }, []);

  // Initialize connection ONCE and setup event listeners
  useEffect(() => {
    if (isInitialized.current) {
      return;
    }

    console.log("[ProctorDashboard] Initializing connection...");
    isInitialized.current = true;

    // Check ProctorAPI availability
    if (window.proctorAPI) {
      setIsConnected(true);
      console.log("[ProctorDashboard] Connected to ProctorAPI");

      // Setup event listeners ONCE
      try {
        // Subscribe to proctor events
        eventUnsubscribe.current = proctorService.onEvent((module, payload, timestamp) => {
          console.log(`[ProctorDashboard] Event from ${module}:`, payload);
          setModuleData((prev) => ({
            ...prev,
            [module]: {
              ...payload,
              lastUpdated: timestamp,
            },
          }));
          setLastUpdate(timestamp);
        });

        // Subscribe to status changes
        statusUnsubscribe.current = proctorService.onStatusChange((status) => {
          console.log("[ProctorDashboard] Worker status update:", status);
          setWorkerStatus(status);
        });

        // Get initial worker status
        proctorService.getWorkerStatus().then((status) => {
          if (status) {
            console.log("[ProctorDashboard] Initial worker status:", status);
            setWorkerStatus(status);
          }
        }).catch(error => {
          console.error("[ProctorDashboard] Error getting initial worker status:", error);
        });

        // Set initial app state to permissions
        setAppState('permissions');

      } catch (error) {
        console.error("[ProctorDashboard] Error setting up event listeners:", error);
      }
    } else {
      console.warn("[ProctorDashboard] ProctorAPI not available");
      setIsConnected(false);
    }

    // Cleanup function
    return () => {
      console.log("[ProctorDashboard] Cleaning up...");
      if (eventUnsubscribe.current) {
        eventUnsubscribe.current();
        eventUnsubscribe.current = null;
      }
      if (statusUnsubscribe.current) {
        statusUnsubscribe.current();
        statusUnsubscribe.current = null;
      }
    };
  }, []); // Empty dependency array - run ONCE

  // Separate effect for initial permission check
  useEffect(() => {
    if (!isConnected || hasCheckedInitialPermissions.current || appState !== 'permissions') {
      return;
    }

    hasCheckedInitialPermissions.current = true;

    // Use a timeout to ensure the UI is ready
    const timer = setTimeout(() => {
      console.log("[ProctorDashboard] Running initial permission check...");
      checkPermissions();
    }, 1000);

    return () => clearTimeout(timer);
  }, [isConnected, appState, checkPermissions]);

  // Module configuration (static)
  const modules = [
    "process-watch",
    "device-watch",
    "bt-watch",
    "screen-watch",
    "notification-blocker",
    "vm-detect",
    "clipboard-worker",
    "focus-idle-watch"
  ];

  const moduleToWorkerName = {
    "process-watch": "process-watch-worker",
    "device-watch": "device-watch-worker",
    "bt-watch": "bt-watch-worker",
    "screen-watch": "screen-watch-worker",
    "notification-blocker": "notification-blocker-worker",
    "vm-detect": "vm-detect-worker",
    "clipboard-worker": "clipboard-worker",
    "focus-idle-watch": "focus-idle-watch-worker"
  };

  // Render connection error
  if (!isConnected) {
    return (
      <div className="proctor-dashboard">
        <div className="connection-error">
          <h2>⚠️ Connection Error</h2>
          <p>Unable to connect to Morpheus proctoring system.</p>
          <p>Please ensure the application is running properly.</p>
        </div>
      </div>
    );
  }

  // Render initial state
  if (appState === 'initial') {
    return (
      <div className="proctor-dashboard">
        <div className="dashboard-header">
          <h1>🛡️ Morpheus Proctoring System</h1>
          <div className="dashboard-status">
            <span className="status-dot pending"></span>
            <span>Initializing...</span>
          </div>
        </div>
        <div className="loading-state">
          <p>Initializing proctoring system...</p>
        </div>
      </div>
    );
  }

  // Render permission view
  if (appState === 'permissions') {
    return (
      <div className="proctor-dashboard">
        <div className="dashboard-header">
          <h1>🛡️ Morpheus Proctoring System</h1>
          <div className="dashboard-status">
            <span className="status-dot pending"></span>
            <span>Checking Permissions</span>
          </div>
        </div>

        <PermissionStatusBadges
          permissionStatus={permissionStatus}
          onRequestPermission={handleRequestPermission}
          onRefreshPermissions={checkPermissions}
          isChecking={isCheckingPermissions}
        />

        <div className="permissions-info">
          <h3>🔐 System Permissions Required</h3>
          <p>
            Morpheus requires specific system permissions to monitor the environment effectively.
            {!permissionStatus && isCheckingPermissions && " Checking permissions automatically..."}
            {permissionStatus && !permissionStatus.allGranted && " Grant missing permissions above and click refresh."}
          </p>

          {/* Debug/Testing button */}
          <div className="action-buttons" style={{ marginTop: "20px" }}>
            <button
              className="btn-primary"
              onClick={() => {
                console.log("[ProctorDashboard] Force switching to dashboard for testing");
                setAppState('dashboard');
              }}
              style={{ marginRight: "10px" }}
            >
              Force Dashboard (Debug)
            </button>

            <button
              className="btn-primary"
              onClick={() => {
                console.log("[ProctorDashboard] Current permission status:", permissionStatus);
                console.log("[ProctorDashboard] Current app state:", appState);
                console.log("[ProctorDashboard] Is checking permissions:", isCheckingPermissions);
              }}
            >
              Debug Status
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Render dashboard view (only when permissions are granted)
  if (appState === 'dashboard') {
    return (
      <div className="proctor-dashboard">
        <div className="dashboard-header">
          <h1>🛡️ Morpheus Proctoring System</h1>
          <div className="dashboard-status">
            <span className="status-dot active"></span>
            <span>System Active</span>
            {lastUpdate && (
              <span className="last-update">
                Last Update: {formatTimestamp(lastUpdate)}
              </span>
            )}
          </div>
        </div>

        <div className="dashboard-grid">
          {modules.map((moduleName) => {
            const moduleInfo = proctorService.getModuleInfo(moduleName);
            const data = moduleData[moduleName];
            const workerFileName = moduleToWorkerName[moduleName];
            const status = workerStatus[workerFileName];
            const threatLevel = getThreatLevel(data);

            return (
              <div
                key={moduleName}
                className={`module-tile ${threatLevel}`}
                style={{ borderLeftColor: moduleInfo.color }}
              >
                <div className="module-header">
                  <div className="module-icon">{moduleInfo.icon}</div>
                  <div className="module-info">
                    <h3>{moduleInfo.name}</h3>
                    <div className="module-status">
                      <span
                        className={`status-indicator ${status?.running ? "running" : "stopped"}`}
                      >
                        {status?.running ? "●" : "○"}
                      </span>
                      <span className="status-text">
                        {status?.running ? "Running" : "Stopped"}
                      </span>
                    </div>
                  </div>
                  <div className="module-actions">
                    <button
                      className="action-btn restart"
                      onClick={() => handleRestartWorker(workerFileName)}
                      title="Restart Worker"
                    >
                      🔄
                    </button>
                  </div>
                </div>

                <div className="module-content">
                  {data ? (
                    <div className="data-display">
                      <div className="threat-level">
                        <span
                          className="threat-dot"
                          style={{
                            backgroundColor: getThreatLevelColor(threatLevel),
                          }}
                        ></span>
                        Threat Level:{" "}
                        <strong
                          style={{ color: getThreatLevelColor(threatLevel) }}
                        >
                          {threatLevel.toUpperCase()}
                        </strong>
                      </div>

                      <div className="data-summary">
                        <div className="data-item">
                          <span className="data-label">Module:</span>
                          <span className="data-value">{data.module || moduleName}</span>
                        </div>

                        <div className="data-item">
                          <span className="data-label">Source:</span>
                          <span className="data-value">{data.source || "unknown"}</span>
                        </div>

                        <div className="data-item">
                          <span className="data-label">Count:</span>
                          <span className="data-value">{data.count || data.counter || 0}</span>
                        </div>

                        <div className="data-item">
                          <span className="data-label">Updated:</span>
                          <span className="data-value">
                            {formatTimestamp(data.lastUpdated)}
                          </span>
                        </div>

                        {/* Module-specific data */}
                        {renderModuleSpecificData(moduleName, data, handleResetNotificationBlocker)}
                      </div>
                    </div>
                  ) : (
                    <div className="no-data">
                      <div className="loading-spinner">⏳</div>
                      <p>Waiting for data...</p>
                    </div>
                  )}
                </div>

                {status && (
                  <div className="module-footer">
                    <small>
                      PID: {status.pid} | Restarts: {status.restartCount || 0} |
                      Uptime: {status.uptime ? Math.floor(status.uptime / 1000) + "s" : "N/A"}
                    </small>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    );
  }

  // Fallback
  return (
    <div className="proctor-dashboard">
      <div className="dashboard-header">
        <h1>🛡️ Morpheus Proctoring System</h1>
        <div className="dashboard-status">
          <span className="status-dot unknown"></span>
          <span>Unknown State</span>
        </div>
      </div>
      <div className="error-state">
        <p>Application is in an unknown state. Please refresh the page.</p>
      </div>
    </div>
  );
};

// Helper function to render module-specific data points
const renderModuleSpecificData = (moduleName, data, handleResetNotificationBlocker) => {
  if (!data) return null;

  switch (moduleName) {
    case "process-watch":
      return (
        <>
          <div className="data-item">
            <span className="data-label">Blacklisted:</span>
            <span className={`data-value ${data.blacklisted_found ? "warning" : "normal"}`}>
              {data.blacklisted_found ? "YES" : "NO"}
            </span>
          </div>
          {data.matches && (
            <div className="data-item">
              <span className="data-label">Matches:</span>
              <span className="data-value warning">{data.matches.length}</span>
            </div>
          )}
        </>
      );

    case "vm-detect":
      return (
        <>
          <div className="data-item">
            <span className="data-label">VM Detected:</span>
            <span className={`data-value ${data.isInsideVM ? "warning" : "normal"}`}>
              {data.isInsideVM ? "YES" : "NO"}
            </span>
          </div>
          {data.detectedVM && data.detectedVM !== "None" && (
            <div className="data-item">
              <span className="data-label">VM Type:</span>
              <span className="data-value warning">{data.detectedVM}</span>
            </div>
          )}
        </>
      );

    case "screen-watch":
      return (
        <>
          <div className="data-item">
            <span className="data-label">Mirroring:</span>
            <span className={`data-value ${data.mirroring ? "warning" : "normal"}`}>
              {data.mirroring ? "DETECTED" : "None"}
            </span>
          </div>
          <div className="data-item">
            <span className="data-label">Displays:</span>
            <span className="data-value">{data.displays?.length || 0}</span>
          </div>
        </>
      );

    case "bt-watch":
      return (
        <>
          <div className="data-item">
            <span className="data-label">Bluetooth:</span>
            <span className={`data-value ${data.enabled ? "normal" : "warning"}`}>
              {data.enabled ? "Enabled" : "Disabled"}
            </span>
          </div>
          <div className="data-item">
            <span className="data-label">Connected:</span>
            <span className="data-value">{data.connectedDevices?.length || 0}</span>
          </div>
        </>
      );

    case "device-watch":
      return (
        <>
          <div className="data-item">
            <span className="data-label">External Devices:</span>
            <span className="data-value">{data.devices?.length || 0}</span>
          </div>
          {data.event && (
            <div className="data-item">
              <span className="data-label">Last Event:</span>
              <span className={`data-value ${
                data.event === "device-connected" ? "normal" :
                data.event === "device-removed" ? "warning" : ""
              }`}>
                {data.event}
              </span>
            </div>
          )}
        </>
      );

    case "notification-blocker":
      return (
        <>
          <div className="data-item">
            <span className="data-label">Status:</span>
            <span className={`data-value ${data.isBlocked ? "normal" : "warning"}`}>
              {data.isBlocked ? "Blocked" : "Enabled"}
            </span>
          </div>
          {data.examActive !== undefined && (
            <div className="data-item">
              <span className="data-label">Exam Mode:</span>
              <span className={`data-value ${data.examActive ? "normal" : "warning"}`}>
                {data.examActive ? "Active" : "Inactive"}
              </span>
            </div>
          )}
          {data.eventType === "violation" && (
            <div className="data-item">
              <span className="data-label">Violation:</span>
              <span className="data-value warning">
                {data.violationType || "Settings Changed"}
              </span>
            </div>
          )}
          {data.reason && (
            <div className="data-item">
              <span className="data-label">Reason:</span>
              <span className="data-value" style={{fontSize: "0.8em"}}>
                {data.reason.replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
              </span>
            </div>
          )}
          <div className="data-item" style={{ marginTop: "10px" }}>
            <button
              className="action-btn reset"
              onClick={handleResetNotificationBlocker}
              title="Reset notification blocking to original state"
              style={{
                backgroundColor: "#f39c12",
                color: "white",
                border: "none",
                padding: "6px 12px",
                borderRadius: "4px",
                cursor: "pointer",
                fontSize: "0.8em"
              }}
            >
              🔄 Reset to Original
            </button>
          </div>
        </>
      );

    case "clipboard-worker":
      return (
        <>
          {data.sourceApp && (
            <div className="data-item">
              <span className="data-label">Source App:</span>
              <span className={`data-value ${data.eventType === "clipboard-changed" ? "warning" : "normal"}`}>
                {data.sourceApp}
              </span>
            </div>
          )}
          {data.contentPreview && (
            <div className="data-item">
              <span className="data-label">Content:</span>
              <span className={`data-value ${data.eventType === "clipboard-changed" ? "warning" : "normal"}`}
                    style={{fontSize: "0.85em", maxWidth: "200px", wordBreak: "break-word"}}>
                {data.contentPreview.length > 50 ?
                  data.contentPreview.substring(0, 50) + "..." :
                  data.contentPreview}
              </span>
            </div>
          )}
          {data.clipFormats && data.clipFormats.length > 0 && (
            <div className="data-item">
              <span className="data-label">Formats:</span>
              <span className="data-value" style={{fontSize: "0.8em"}}>
                {data.clipFormats.length} types
              </span>
            </div>
          )}
          {data.isSensitive !== undefined && (
            <div className="data-item">
              <span className="data-label">Sensitive:</span>
              <span className={`data-value ${data.isSensitive ? "warning" : "normal"}`}>
                {data.isSensitive ? "YES" : "NO"}
              </span>
            </div>
          )}
          {data.privacyMode !== undefined && (
            <div className="data-item">
              <span className="data-label">Privacy:</span>
              <span className="data-value">
                {data.privacyMode === 0 ? "Metadata" : data.privacyMode === 1 ? "Redacted" : "Full"}
              </span>
            </div>
          )}
        </>
      );

    case "focus-idle-watch":
      return (
        <>
          <div className="data-item">
            <span className="data-label">Event:</span>
            <span className={`data-value ${
              data.eventType === "focus-lost" || data.eventType === "idle-start" ? "warning" : "normal"
            }`}>
              {data.eventType || "monitoring"}
            </span>
          </div>
          {data.details?.activeApp && (
            <div className="data-item">
              <span className="data-label">Active App:</span>
              <span className="data-value">{data.details.activeApp}</span>
            </div>
          )}
        </>
      );

    default:
      return (
        <div className="data-item">
          <span className="data-label">Status:</span>
          <span className="data-value">{data.status || "Active"}</span>
        </div>
      );
  }
};

export default ProctorDashboard;