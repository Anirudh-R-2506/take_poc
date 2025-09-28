import React, { useState, useEffect, useCallback, useRef } from "react";
import proctorService from "./proctorService";
import PermissionStatusBadges from "./components/PermissionStatusBadges";
import ViolationsBanner from "./components/ViolationsBanner";
import "./ProctorDashboard.css";

// Process table component
const ProcessTable = ({ processes = [], pageSize = 10 }) => {
  const [currentPage, setCurrentPage] = useState(0);
  const [sortField, setSortField] = useState('name');
  const [sortDirection, setSortDirection] = useState('asc');

  const sortedProcesses = React.useMemo(() => {
    if (!processes || !Array.isArray(processes)) return [];

    return [...processes].sort((a, b) => {
      let aVal = a[sortField] || '';
      let bVal = b[sortField] || '';

      if (sortField === 'pid') {
        aVal = parseInt(aVal) || 0;
        bVal = parseInt(bVal) || 0;
      } else if (typeof aVal === 'string') {
        aVal = aVal.toLowerCase();
        bVal = bVal.toLowerCase();
      }

      if (sortDirection === 'asc') {
        return aVal < bVal ? -1 : aVal > bVal ? 1 : 0;
      } else {
        return aVal > bVal ? -1 : aVal < bVal ? 1 : 0;
      }
    });
  }, [processes, sortField, sortDirection]);

  const totalPages = Math.ceil(sortedProcesses.length / pageSize);
  const startIndex = currentPage * pageSize;
  const endIndex = startIndex + pageSize;
  const currentProcesses = sortedProcesses.slice(startIndex, endIndex);

  const handleSort = (field) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('asc');
    }
  };

  const getSortIcon = (field) => {
    if (sortField !== field) return '↕️';
    return sortDirection === 'asc' ? '↑' : '↓';
  };

  if (!processes || processes.length === 0) {
    return (
      <div className="process-table-container">
        <h4>Active Processes</h4>
        <div className="no-processes">No process data available</div>
      </div>
    );
  }

  return (
    <div className="process-table-container">
      <h4>Active Processes ({processes.length} total)</h4>

      <table className="process-table">
        <thead>
          <tr>
            <th onClick={() => handleSort('name')} className="sortable">
              Process Name {getSortIcon('name')}
            </th>
            <th onClick={() => handleSort('pid')} className="sortable">
              PID {getSortIcon('pid')}
            </th>
            <th onClick={() => handleSort('path')} className="sortable">
              Path {getSortIcon('path')}
            </th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {currentProcesses.map((process, index) => {
            const isFlagged = process.flagged || process.suspicious || process.blacklisted;
            return (
              <tr key={`${process.pid}-${index}`} className={isFlagged ? 'flagged-process' : ''}>
                <td className="process-name">
                  {isFlagged && <span className="flag-indicator">🚩</span>}
                  {process.name || 'Unknown'}
                </td>
                <td className="process-pid">{process.pid || 'N/A'}</td>
                <td className="process-path" title={process.path || process.executablePath}>
                  {(process.path || process.executablePath || 'Unknown').length > 50
                    ? (process.path || process.executablePath || 'Unknown').substring(0, 50) + '...'
                    : (process.path || process.executablePath || 'Unknown')}
                </td>
                <td className="process-status">
                  {isFlagged ? (
                    <span className="status-flagged">FLAGGED</span>
                  ) : (
                    <span className="status-normal">Normal</span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>

      {totalPages > 1 && (
        <div className="pagination">
          <button
            onClick={() => setCurrentPage(Math.max(0, currentPage - 1))}
            disabled={currentPage === 0}
            className="pagination-btn"
          >
            Previous
          </button>

          <span className="pagination-info">
            Page {currentPage + 1} of {totalPages}
          </span>

          <button
            onClick={() => setCurrentPage(Math.min(totalPages - 1, currentPage + 1))}
            disabled={currentPage === totalPages - 1}
            className="pagination-btn"
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
};

// Component for paginated process violations table
const ProcessViolationsTable = ({ violations }) => {
  const [currentPage, setCurrentPage] = useState(0);
  const itemsPerPage = 5;

  // Calculate pagination
  const totalPages = Math.ceil(violations.length / itemsPerPage);
  const startIndex = currentPage * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const currentViolations = violations.slice(startIndex, endIndex);

  const goToPage = (page) => {
    setCurrentPage(Math.max(0, Math.min(page, totalPages - 1)));
  };

  return (
    <div className="violations-table-container">
      <div className="violations-table-header">
        <h5>Process Violations ({violations.length})</h5>
      </div>

      <div className="violations-table">
        <div className="table-header">
          <div className="col-process">Process</div>
          <div className="col-pid">PID</div>
          <div className="col-threat">Threat</div>
          <div className="col-category">Category</div>
          <div className="col-confidence">Confidence</div>
        </div>

        <div className="table-body">
          {currentViolations.map((violation, index) => (
            <div key={startIndex + index} className="table-row">
              <div className="col-process">
                <div className="process-name">{violation.name || 'Unknown Process'}</div>
                {violation.riskReason && (
                  <div className="process-description">{violation.riskReason}</div>
                )}
              </div>
              <div className="col-pid">{violation.pid}</div>
              <div className="col-threat">
                <span className={`threat-badge ${violation.threatLevel?.toLowerCase()}`}>
                  {violation.threatLevel}
                </span>
              </div>
              <div className="col-category">{violation.category}</div>
              <div className="col-confidence">
                {violation.confidence ? `${Math.round(violation.confidence * 100)}%` : 'N/A'}
              </div>
            </div>
          ))}
        </div>

        {totalPages > 1 && (
          <div className="table-pagination">
            <button
              className="pagination-btn"
              onClick={() => goToPage(currentPage - 1)}
              disabled={currentPage === 0}
            >
              ‹ Previous
            </button>

            <div className="pagination-info">
              Page {currentPage + 1} of {totalPages}
            </div>

            <button
              className="pagination-btn"
              onClick={() => goToPage(currentPage + 1)}
              disabled={currentPage === totalPages - 1}
            >
              Next ›
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

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

  // Exam monitoring state
  const [examExited, setExamExited] = useState(false);
  const [examExitReason, setExamExitReason] = useState('');
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [notificationResetStatus, setNotificationResetStatus] = useState(null);

  // Manual permission check function (for refresh button)
  const checkPermissions = useCallback(async () => {
    if (isCheckingPermissions) {
      return;
    }

    setIsCheckingPermissions(true);

    try {
      if (window.proctorAPI && window.proctorAPI.checkPermissions) {
        const status = await window.proctorAPI.checkPermissions();
        setPermissionStatus(status);

        // If all permissions are granted after manual retry, start workers and proceed
        if (status && status.allGranted) {
          try {
            if (window.proctorAPI.startWorkers) {
              const result = await window.proctorAPI.startWorkers();
              setAppState('dashboard');
            } else {
              setAppState('dashboard');
            }
          } catch (workerError) {
            // Still switch to dashboard even if there's an error
            setAppState('dashboard');
          }
        } else {
          setAppState('permissions');
        }
      }
    } catch (error) {
      // Error handling without logging
    } finally {
      setIsCheckingPermissions(false);
    }
  }, [isCheckingPermissions]);

  // Request specific permission
  const handleRequestPermission = useCallback(async (permissionType) => {
    try {
      if (window.proctorAPI && window.proctorAPI.requestPermission) {
        await window.proctorAPI.requestPermission(permissionType);
      }
    } catch (error) {
      // Error handling without logging
    }
  }, []);

  // Restart worker function
  const handleRestartWorker = useCallback(async (moduleName) => {
    try {
      const success = await proctorService.restartWorker(moduleName);
    } catch (error) {
      // Error handling without logging
    }
  }, []);

  // Reset notification blocker to original state
  const handleResetNotificationBlocker = useCallback(async () => {
    try {
      setNotificationResetStatus('resetting');

      // Send reset command to the notification-blocker worker
      if (window.proctorAPI && window.proctorAPI.sendWorkerCommand) {
        const success = await window.proctorAPI.sendWorkerCommand('notification-blocker-worker', {
          cmd: 'resetToOriginal',
          timestamp: Date.now()
        });

        if (success) {
          setNotificationResetStatus('success');
          alert('Focus Assist has been successfully reset to the original state that was active before opening the app.');

          // Clear status after 3 seconds
          setTimeout(() => {
            setNotificationResetStatus(null);
          }, 3000);
        } else {
          setNotificationResetStatus('failed');
          alert('Failed to reset Focus Assist. The reset command could not be sent to the notification blocker.');

          setTimeout(() => {
            setNotificationResetStatus(null);
          }, 3000);
        }
      } else {
        setNotificationResetStatus('failed');
        alert('Cannot reset Focus Assist: ProctorAPI is not available for worker communication.');

        setTimeout(() => {
          setNotificationResetStatus(null);
        }, 3000);
      }
    } catch (error) {
      setNotificationResetStatus('failed');
      alert(`Error resetting Focus Assist: ${error.message}`);

      setTimeout(() => {
        setNotificationResetStatus(null);
      }, 3000);
    }
  }, []);

  // Utility functions
  const formatTimestamp = useCallback((timestamp) => {
    if (!timestamp) return "Never";
    return new Date(timestamp).toLocaleTimeString();
  }, []);

  const getThreatLevel = useCallback((data) => {
    if (!data) return "unknown";

    // Enhanced data structure - check for max_threat_level first
    if (data.max_threat_level) {
      switch (data.max_threat_level.toUpperCase()) {
        case 'CRITICAL': return "high";
        case 'HIGH': return "high";
        case 'MEDIUM': return "normal";
        case 'LOW': return "low";
        case 'NONE': return "low";
        default: break;
      }
    }

    // Enhanced data - check violations
    if (data.violations && data.violations.length > 0) {
      const hasCritical = data.violations.some(v => v.threatLevel === 'CRITICAL');
      const hasHigh = data.violations.some(v => v.threatLevel === 'HIGH');
      if (hasCritical || hasHigh) return "high";

      const hasMedium = data.violations.some(v => v.threatLevel === 'MEDIUM');
      if (hasMedium) return "normal";
    }

    // Enhanced screen sharing detection
    if (data.isScreenCaptured === true) return "high";
    if (data.total_sessions > 0) return "high";

    // Legacy threat indicators
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

    isInitialized.current = true;

    // Check ProctorAPI availability
    if (window.proctorAPI) {
      setIsConnected(true);

      // Setup event listeners ONCE
      try {
        // Subscribe to proctor events
        eventUnsubscribe.current = proctorService.onEvent((module, payload, timestamp) => {
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
          setWorkerStatus(status);
        });

        // Get initial worker status
        proctorService.getWorkerStatus().then((status) => {
          if (status) {
            setWorkerStatus(status);
          }
        }).catch(error => {
          // Error handling without logging
        });

        // Set initial app state to permissions
        setAppState('permissions');

      } catch (error) {
        // Error handling without logging
      }
    } else {
      setIsConnected(false);
    }

    // Cleanup function
    return () => {
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
      checkPermissions();
    }, 1000);

    return () => clearTimeout(timer);
  }, [isConnected, appState, checkPermissions]);

  // Fullscreen and focus monitoring effect
  useEffect(() => {
    if (appState !== 'dashboard') return;

    const handleFullscreenChange = () => {
      const isCurrentlyFullscreen = !!document.fullscreenElement;
      setIsFullscreen(isCurrentlyFullscreen);

      if (!isCurrentlyFullscreen && isFullscreen) {
        setExamExited(true);
        setExamExitReason('Fullscreen mode was disabled');
      }
    };

    const handleVisibilityChange = () => {
      if (document.hidden) {
        setExamExited(true);
        setExamExitReason('Window focus was lost (Alt+Tab, Cmd+Tab, or window switching detected)');
      }
    };

    const handleBlur = () => {
      setExamExited(true);
      setExamExitReason('Application lost focus');
    };

    // Add event listeners
    document.addEventListener('fullscreenchange', handleFullscreenChange);
    document.addEventListener('visibilitychange', handleVisibilityChange);
    window.addEventListener('blur', handleBlur);

    // Force fullscreen on dashboard load
    if (appState === 'dashboard' && !document.fullscreenElement) {
      document.documentElement.requestFullscreen().then(() => {
        setIsFullscreen(true);
      }).catch((err) => {
        // Error handling without logging
      });
    }

    return () => {
      document.removeEventListener('fullscreenchange', handleFullscreenChange);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      window.removeEventListener('blur', handleBlur);
    };
  }, [appState, isFullscreen]);

  // Module configuration (static)
  const modules = [
    "process-watch",
    "device-watch", // Includes Bluetooth detection via SmartDeviceDetector
    "screen-watch",
    "notification-blocker",
    "vm-detect",
    "clipboard-worker",
    "focus-idle-watch"
  ];

  const moduleToWorkerName = {
    "process-watch": "process-watch-worker",
    "device-watch": "device-watch-worker",
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
                setAppState('dashboard');
              }}
              style={{ marginRight: "10px" }}
            >
              Force Dashboard (Debug)
            </button>

            <button
              className="btn-primary"
              onClick={() => {
                // Debug functionality without logging
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
        {examExited && (
          <div className="exam-exit-banner">
            <div className="exam-exit-content">
              <span className="exam-exit-icon">⚠️</span>
              <div className="exam-exit-text">
                <strong>EXAM EXITED</strong>
                <p>{examExitReason}</p>
              </div>
            </div>
          </div>
        )}

        <div className="dashboard-header">
          <h1>🛡️ Morpheus Proctoring System</h1>
          <div className="dashboard-status">
            <span className={`status-dot ${examExited ? 'error' : 'active'}`}></span>
            <span>{examExited ? 'Exam Exited' : 'System Active'}</span>
            {lastUpdate && (
              <span className="last-update">
                Last Update: {formatTimestamp(lastUpdate)}
              </span>
            )}
            {isFullscreen && (
              <span className="fullscreen-indicator">🔒 Fullscreen Active</span>
            )}
          </div>
        </div>

        <ViolationsBanner
          moduleData={moduleData}
          examExited={examExited}
          examExitReason={examExitReason}
        />

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
                    <div className="threat-level">
                      <span
                        className="threat-dot"
                        style={{
                          backgroundColor: getThreatLevelColor(threatLevel),
                        }}
                      ></span>
                      <strong
                        style={{ color: getThreatLevelColor(threatLevel) }}
                      >
                        {threatLevel.toUpperCase()}
                      </strong>
                    </div>
                  </div>
                </div>

                <div className="module-content">
                  {data ? (
                    <div className="data-display">
                      <div className="data-summary">
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
            <span className="data-label">Status:</span>
            <span className={`data-value ${data.violations?.length > 0 ? "warning" : "normal"}`}>
              {data.violations?.length > 0 ? `${data.violations.length} Violations` : "Clean"}
            </span>
          </div>
          {data.max_threat_level && data.max_threat_level !== 'NONE' && (
            <div className="data-item">
              <span className="data-label">Threat Level:</span>
              <span className={`data-value ${data.max_threat_level === 'CRITICAL' || data.max_threat_level === 'HIGH' ? "warning" : "normal"}`}>
                {data.max_threat_level}
              </span>
            </div>
          )}
          {data.violations && data.violations.length > 0 && (
            <div className="data-item full-width">
              <ProcessViolationsTable violations={data.violations} />
            </div>
          )}
        </>
      );

    case "vm-detect":
      return (
        <>
          <div className="data-item">
            <span className="data-label">Status:</span>
            <span className={`data-value ${data.isInsideVM ? "warning" : "normal"}`}>
              {data.isInsideVM ? "VM Detected" : "Physical Machine"}
            </span>
          </div>
          {data.isInsideVM && (
            <>
              <div className="data-item">
                <span className="data-label">Violation:</span>
                <span className="data-value warning">Virtual Machine</span>
              </div>
              {data.detectedVM && data.detectedVM !== "None" && (
                <div className="data-item">
                  <span className="data-label">VM Type:</span>
                  <span className="data-value warning">{data.detectedVM}</span>
                </div>
              )}
              {data.confidence && (
                <div className="data-item">
                  <span className="data-label">Confidence:</span>
                  <span className="data-value">{Math.round(data.confidence * 100)}%</span>
                </div>
              )}
            </>
          )}
        </>
      );

    case "screen-watch":
      return (
        <>
          <div className="data-item">
            <span className="data-label">Status:</span>
            <span className={`data-value ${data.isScreenCaptured || data.total_sessions > 0 ? "warning" : "normal"}`}>
              {data.isScreenCaptured ? "Screen Captured" :
               data.total_sessions > 0 ? `${data.total_sessions} Active Sessions` : "Secure"}
            </span>
          </div>
          {data.max_threat_level && data.max_threat_level !== 'NONE' && (
            <div className="data-item">
              <span className="data-label">Threat Level:</span>
              <span className={`data-value ${data.max_threat_level === 'CRITICAL' || data.max_threat_level === 'HIGH' ? "warning" : "normal"}`}>
                {data.max_threat_level}
              </span>
            </div>
          )}
          {data.violations && data.violations.length > 0 && (
            <>
              <div className="data-item">
                <span className="data-label">Violations:</span>
                <span className="data-value warning">
                  {data.violations.length} detected
                </span>
              </div>
              <div className="data-item full-width">
                <div className="violations-container">
                  <h5>Screen Sharing Violations:</h5>
                  {data.violations.slice(0, 3).map((violation, index) => (
                    <div key={index} className="violation-item">
                      <div className="violation-header">
                        <strong>{violation.appName || 'Unknown App'}</strong>
                        <span className={`threat-badge ${violation.threatLevel?.toLowerCase()}`}>
                          {violation.threatLevel}
                        </span>
                      </div>
                      <div className="violation-details">
                        <span>Method: {violation.method}</span>
                        {violation.confidence && <span>Confidence: {Math.round(violation.confidence * 100)}%</span>}
                      </div>
                      {violation.details && (
                        <div className="violation-description">
                          {violation.details}
                        </div>
                      )}
                    </div>
                  ))}
                  {data.violations.length > 3 && (
                    <div className="more-violations">
                      +{data.violations.length - 3} more violations
                    </div>
                  )}
                </div>
              </div>
            </>
          )}
        </>
      );


    case "device-watch":
      const totalViolations = data.violations?.length || 0;
      const totalDevices = (data.storageDevices?.length || 0) + (data.inputDevices?.length || 0) + (data.videoDevices?.length || 0);
      const externalDevices = (data.inputDevices?.filter(d => d.isExternal)?.length || 0) +
                             (data.storageDevices?.filter(d => d.isExternal)?.length || 0);

      return (
        <>
          <div className="data-item">
            <span className="data-label">Status:</span>
            <span className={`data-value ${totalViolations > 0 ? "warning" : "normal"}`}>
              {totalViolations > 0 ? `${totalViolations} Violations` : "Secure"}
            </span>
          </div>
          <div className="data-item">
            <span className="data-label">External Devices:</span>
            <span className={`data-value ${externalDevices > 0 ? "warning" : "normal"}`}>
              {externalDevices}
            </span>
          </div>
          <div className="data-item">
            <span className="data-label">Total Devices:</span>
            <span className="data-value">{totalDevices}</span>
          </div>
          {totalViolations > 0 && (
            <div className="data-item full-width">
              <div className="violations-container">
                <h5>Device Violations:</h5>
                {data.violations.slice(0, 3).map((violation, index) => (
                  <div key={index} className="violation-item">
                    <div className="violation-header">
                      <strong>{violation.deviceName || 'Unknown Device'}</strong>
                      <span className={`threat-badge ${
                        violation.severity === 4 ? 'critical' :
                        violation.severity === 3 ? 'high' :
                        violation.severity === 2 ? 'medium' : 'low'
                      }`}>
                        {violation.severity === 4 ? 'CRITICAL' :
                         violation.severity === 3 ? 'HIGH' :
                         violation.severity === 2 ? 'MEDIUM' : 'LOW'}
                      </span>
                    </div>
                    <div className="violation-details">
                      <span>Type: {violation.violationType}</span>
                      <span>Device: {violation.deviceType || 'Unknown'}</span>
                    </div>
                    {violation.reason && (
                      <div className="violation-description">
                        {violation.reason}
                      </div>
                    )}
                  </div>
                ))}
                {totalViolations > 3 && (
                  <div className="more-violations">
                    +{totalViolations - 3} more violations
                  </div>
                )}
              </div>
            </div>
          )}
        </>
      );

    case "notification-blocker":
      return (
        <>
          <div className="data-item">
            <span className="data-label">Notifications:</span>
            <span className={`data-value ${data.isBlocked ? "normal" : "warning"}`}>
              {data.isBlocked ? "Blocked" : "Enabled"}
            </span>
          </div>
          <div className="data-item">
            <span className="data-label">Exam Mode:</span>
            <span className={`data-value ${data.examActive ? "normal" : "warning"}`}>
              {data.examActive ? "Active" : "Inactive"}
            </span>
          </div>
          {/* Show notification violations */}
          {data.eventType === "violation" && (
            <>
              <div className="data-item">
                <span className="data-label">Violation:</span>
                <span className="data-value warning">
                  {data.violationType || "Settings Modified"}
                </span>
              </div>
              {data.reason && (
                <div className="data-item">
                  <span className="data-label">Details:</span>
                  <span className="data-value warning" style={{fontSize: "0.8em"}}>
                    {data.reason.replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                  </span>
                </div>
              )}
            </>
          )}
          {data.eventType === "notification-arrived" && (
            <>
              <div className="data-item">
                <span className="data-label">Violation:</span>
                <span className="data-value warning">
                  Notification Received
                </span>
              </div>
              {data.notificationTitle && (
                <div className="data-item">
                  <span className="data-label">Title:</span>
                  <span className="data-value" style={{fontSize: "0.8em"}}>
                    {data.notificationTitle}
                  </span>
                </div>
              )}
            </>
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
          <div className="data-item">
            <span className="data-label">Protection:</span>
            <span className={`data-value ${data.activeClearingEnabled ? "normal" : "warning"}`}>
              {data.activeClearingEnabled ? "Active Clearing" : "Monitoring Only"}
            </span>
          </div>
          <div className="data-item">
            <span className="data-label">Status:</span>
            <span className={`data-value ${
              data.eventType === "clipboard-cleared" ? "normal" :
              data.eventType === "clipboard-changed" ? "warning" : "normal"
            }`}>
              {data.eventType === "clipboard-cleared" ? "Content Cleared" :
               data.eventType === "clipboard-changed" ? "Content Detected" :
               data.currentStatus === 'content-detected-and-cleared' ? "Content Cleared" :
               "Monitoring"}
            </span>
          </div>
          {/* Show clipboard clearing actions */}
          {data.eventType === "clipboard-cleared" && (
            <>
              <div className="data-item">
                <span className="data-label">Action:</span>
                <span className="data-value normal">🔄 Auto-Cleared</span>
              </div>
              {data.originalContent && (
                <div className="data-item">
                  <span className="data-label">Detected Content:</span>
                  <span className="data-value" style={{fontSize: "0.8em", maxWidth: "200px", wordBreak: "break-word"}}>
                    {data.originalContent.length > 30 ?
                      data.originalContent.substring(0, 30) + "..." :
                      data.originalContent}
                  </span>
                </div>
              )}
              {data.sourceApp && (
                <div className="data-item">
                  <span className="data-label">Source App:</span>
                  <span className="data-value">{data.sourceApp}</span>
                </div>
              )}
            </>
          )}
          {/* Show current clipboard content violations */}
          {data.eventType === "clipboard-changed" && data.contentPreview && (
            <>
              <div className="data-item">
                <span className="data-label">Violation:</span>
                <span className="data-value warning">Content Detected</span>
              </div>
              <div className="data-item">
                <span className="data-label">Content Preview:</span>
                <span className="data-value warning"
                      style={{fontSize: "0.8em", maxWidth: "200px", wordBreak: "break-word"}}>
                  {data.contentPreview.length > 30 ?
                    data.contentPreview.substring(0, 30) + "..." :
                    data.contentPreview}
                </span>
              </div>
              {data.sourceApp && (
                <div className="data-item">
                  <span className="data-label">Source App:</span>
                  <span className="data-value">{data.sourceApp}</span>
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
            </>
          )}
        </>
      );

    case "focus-idle-watch":
      return (
        <>
          <div className="data-item">
            <span className="data-label">Focus Status:</span>
            <span className={`data-value ${
              data.eventType === "focus-lost" || data.eventType === "idle-start" ? "warning" : "normal"
            }`}>
              {data.eventType === "focus-lost" ? "Lost Focus" :
               data.eventType === "idle-start" ? "User Idle" :
               data.eventType === "focus-gained" ? "Focused" : "Active"}
            </span>
          </div>
          {/* Show focus violation details */}
          {data.eventType === "focus-lost" && (
            <>
              <div className="data-item">
                <span className="data-label">Violation:</span>
                <span className="data-value warning">Focus Lost</span>
              </div>
              {data.details?.activeApp && (
                <div className="data-item">
                  <span className="data-label">Switched To:</span>
                  <span className="data-value warning">{data.details.activeApp}</span>
                </div>
              )}
              {data.details?.duration && (
                <div className="data-item">
                  <span className="data-label">Duration:</span>
                  <span className="data-value">{data.details.duration}s</span>
                </div>
              )}
            </>
          )}
          {/* Show idle violation details */}
          {data.eventType === "idle-start" && (
            <>
              <div className="data-item">
                <span className="data-label">Violation:</span>
                <span className="data-value warning">User Idle</span>
              </div>
              {data.details?.idleDuration && (
                <div className="data-item">
                  <span className="data-label">Idle Time:</span>
                  <span className="data-value">{data.details.idleDuration}s</span>
                </div>
              )}
            </>
          )}
        </>
      );

    case "recorder-overlay-watch":
      return (
        <>
          <div className="data-item">
            <span className="data-label">Status:</span>
            <span className={`data-value ${
              data.recordingProcesses?.length > 0 || data.overlayWindows?.length > 0 ? "warning" : "normal"
            }`}>
              {data.recordingProcesses?.length > 0 ? `${data.recordingProcesses.length} Recording` :
               data.overlayWindows?.length > 0 ? `${data.overlayWindows.length} Overlays` : "Secure"}
            </span>
          </div>
          {data.eventType === "recording-violation" && (
            <>
              <div className="data-item">
                <span className="data-label">Violation:</span>
                <span className="data-value warning">Recording Detected</span>
              </div>
              {data.recordingProcesses && data.recordingProcesses.length > 0 && (
                <div className="data-item">
                  <span className="data-label">Recording Apps:</span>
                  <span className="data-value warning">
                    {data.recordingProcesses.slice(0, 2).map(p => p.name || p.processName).join(", ")}
                    {data.recordingProcesses.length > 2 && ` +${data.recordingProcesses.length - 2} more`}
                  </span>
                </div>
              )}
            </>
          )}
          {data.eventType === "overlay-violation" && (
            <>
              <div className="data-item">
                <span className="data-label">Violation:</span>
                <span className="data-value warning">Overlay Detected</span>
              </div>
              {data.overlayWindows && data.overlayWindows.length > 0 && (
                <div className="data-item">
                  <span className="data-label">Overlay Windows:</span>
                  <span className="data-value warning">
                    {data.overlayWindows.slice(0, 2).map(w => w.title || w.name).join(", ")}
                    {data.overlayWindows.length > 2 && ` +${data.overlayWindows.length - 2} more`}
                  </span>
                </div>
              )}
            </>
          )}
          {data.confidence && (
            <div className="data-item">
              <span className="data-label">Confidence:</span>
              <span className="data-value">{Math.round(data.confidence * 100)}%</span>
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