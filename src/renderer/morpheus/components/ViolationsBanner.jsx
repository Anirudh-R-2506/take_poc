import React, { useState, useEffect, useCallback } from "react";
import "./ViolationsBanner.css";

// Component for paginated violations table (similar to ProcessViolationsTable)
const AllViolationsTable = ({ violations, title }) => {
  const [currentPage, setCurrentPage] = useState(0);
  const [sortField, setSortField] = useState("timestamp");
  const [sortDirection, setSortDirection] = useState("desc");
  const itemsPerPage = 10;

  const sortedViolations = React.useMemo(() => {
    if (!violations || !Array.isArray(violations)) return [];

    return [...violations].sort((a, b) => {
      let aVal = a[sortField] || "";
      let bVal = b[sortField] || "";

      if (sortField === "timestamp") {
        aVal = parseInt(aVal) || 0;
        bVal = parseInt(bVal) || 0;
      } else if (typeof aVal === "string") {
        aVal = aVal.toLowerCase();
        bVal = bVal.toLowerCase();
      }

      if (sortDirection === "asc") {
        return aVal < bVal ? -1 : aVal > bVal ? 1 : 0;
      } else {
        return aVal > bVal ? -1 : aVal < bVal ? 1 : 0;
      }
    });
  }, [violations, sortField, sortDirection]);

  // Calculate pagination
  const totalPages = Math.ceil(sortedViolations.length / itemsPerPage);
  const startIndex = currentPage * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const currentViolations = sortedViolations.slice(startIndex, endIndex);

  const handleSort = (field) => {
    if (sortField === field) {
      setSortDirection(sortDirection === "asc" ? "desc" : "asc");
    } else {
      setSortField(field);
      setSortDirection("asc");
    }
  };

  const getSortIcon = (field) => {
    if (sortField !== field) return "↕️";
    return sortDirection === "asc" ? "↑" : "↓";
  };

  const goToPage = (page) => {
    setCurrentPage(Math.max(0, Math.min(page, totalPages - 1)));
  };

  const getSeverityColor = (severity) => {
    switch (severity?.toUpperCase()) {
      case "CRITICAL":
        return "#e74c3c";
      case "HIGH":
        return "#e67e22";
      case "MEDIUM":
        return "#f39c12";
      case "LOW":
        return "#95a5a6";
      default:
        return "#95a5a6";
    }
  };

  const formatTime = (timestamp) => {
    return new Date(timestamp).toLocaleTimeString();
  };

  const getModuleIcon = (module) => {
    const icons = {
      "process-watch": "🔍",
      "device-watch": "💾",
      "screen-watch": "🖥️",
      "notification-blocker": "🔕",
      "vm-detect": "🖴",
      "clipboard-worker": "📋",
      "focus-idle-watch": "🎯",
      system: "⚠️",
    };
    return icons[module] || "❓";
  };

  return (
    <div className="violations-table-container">
      <div className="violations-table-header">
        <h5>
          {title} ({violations.length})
        </h5>
      </div>

      <div className="violations-table">
        <div className="table-header">
          <div
            className="col-time"
            onClick={() => handleSort("timestamp")}
            style={{ cursor: "pointer" }}
          >
            Time {getSortIcon("timestamp")}
          </div>
          <div
            className="col-module"
            onClick={() => handleSort("module")}
            style={{ cursor: "pointer" }}
          >
            Module {getSortIcon("module")}
          </div>
          <div
            className="col-device"
            onClick={() => handleSort("deviceName")}
            style={{ cursor: "pointer" }}
          >
            Device/Source {getSortIcon("deviceName")}
          </div>
          <div
            className="col-violation"
            onClick={() => handleSort("violationType")}
            style={{ cursor: "pointer" }}
          >
            Violation {getSortIcon("violationType")}
          </div>
          <div
            className="col-severity"
            onClick={() => handleSort("severity")}
            style={{ cursor: "pointer" }}
          >
            Severity {getSortIcon("severity")}
          </div>
          <div className="col-reason">Reason</div>
        </div>

        <div className="table-body">
          {currentViolations.map((violation, index) => (
            <div key={violation.id || startIndex + index} className="table-row">
              <div className="col-time">{formatTime(violation.timestamp)}</div>
              <div className="col-module">
                <span>
                  {getModuleIcon(violation.module)} {violation.module}
                </span>
              </div>
              <div className="col-device">
                <div className="device-name">
                  {violation.deviceName || "Unknown"}
                </div>
              </div>
              <div className="col-violation">{violation.violationType}</div>
              <div className="col-severity">
                <span
                  className="severity-badge"
                  style={{
                    backgroundColor: getSeverityColor(violation.severity),
                    color: "white",
                    padding: "2px 8px",
                    borderRadius: "12px",
                    fontSize: "0.8em",
                  }}
                >
                  {violation.severity}
                </span>
              </div>
              <div className="col-reason">
                <div className="reason-text">{violation.reason}</div>
                {violation.evidence && (
                  <div
                    className="evidence-text"
                    style={{
                      fontSize: "0.8em",
                      color: "#666",
                      marginTop: "2px",
                    }}
                  >
                    {violation.evidence}
                  </div>
                )}
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
              Page {currentPage + 1} of {totalPages} ({violations.length} total)
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

const ViolationsBanner = ({ moduleData, examExited, examExitReason }) => {
  const [violationHistory, setViolationHistory] = useState([]);
  const [activeViolations, setActiveViolations] = useState([]);
  const [isExpanded, setIsExpanded] = useState(false);
  const [lastViolationTime, setLastViolationTime] = useState(null);

  // Extract all violations from module data
  const extractViolations = useCallback((data) => {
    const violations = [];
    const timestamp = Date.now();

    Object.entries(data).forEach(([module, moduleData]) => {
      if (
        moduleData &&
        moduleData.violations &&
        Array.isArray(moduleData.violations)
      ) {
        moduleData.violations.forEach((violation) => {
          violations.push({
            id: `${module}-${violation.deviceId || violation.deviceName || Math.random()}`,
            module,
            timestamp,
            ...violation,
            // Normalize severity levels
            severity:
              typeof violation.severity === "number"
                ? violation.severity === 4
                  ? "CRITICAL"
                  : violation.severity === 3
                    ? "HIGH"
                    : violation.severity === 2
                      ? "MEDIUM"
                      : "LOW"
                : violation.severity || violation.threatLevel || "MEDIUM",
          });
        });
      }

      // Handle process violations differently
      if (module === "process-watch" && moduleData) {
        if (moduleData.blacklisted_found) {
          violations.push({
            id: `process-blacklisted-${timestamp}`,
            module,
            timestamp,
            deviceName: "Blacklisted Process",
            violationType: "blacklisted-process",
            severity: "CRITICAL",
            reason: "Blacklisted process detected on system",
            evidence: `Max threat level: ${moduleData.max_threat_level || "HIGH"}`,
          });
        }
      }

      // Handle screen capture violations
      if (module === "screen-watch" && moduleData) {
        if (moduleData.isScreenCaptured) {
          violations.push({
            id: `screen-capture-${timestamp}`,
            module,
            timestamp,
            deviceName: "Screen Capture",
            violationType: "screen-sharing",
            severity: "CRITICAL",
            reason: "Screen sharing or recording detected",
            evidence: `Sessions: ${moduleData.total_sessions || 1}`,
          });
        }
      }

      // Handle VM detection violations
      if (module === "vm-detect" && moduleData && moduleData.isInsideVM) {
        violations.push({
          id: `vm-detection-${timestamp}`,
          module,
          timestamp,
          deviceName: "Virtual Machine",
          violationType: "virtual-environment",
          severity: "CRITICAL",
          reason: "Virtual machine environment detected",
          evidence: `VM Type: ${moduleData.detectedVM || "Unknown"}`,
        });
      }

      // Handle clipboard violations
      if (
        module === "clipboard-worker" &&
        moduleData &&
        moduleData.eventType === "clipboard-changed"
      ) {
        violations.push({
          id: `clipboard-${timestamp}`,
          module,
          timestamp,
          deviceName: "Clipboard Activity",
          violationType: "clipboard-change",
          severity: "MEDIUM",
          reason: "Clipboard content changed during exam",
          evidence: `Source: ${moduleData.sourceApp || "Unknown"}`,
        });
      }

      // Handle focus violations
      if (module === "focus-idle-watch" && moduleData) {
        if (
          moduleData.eventType === "focus-lost" ||
          moduleData.eventType === "idle-start"
        ) {
          violations.push({
            id: `focus-${timestamp}`,
            module,
            timestamp,
            deviceName: "Focus/Window Switch",
            violationType: "focus-violation",
            severity: "HIGH",
            reason: "Application focus lost or window switching detected",
            evidence: `Event: ${moduleData.eventType}, App: ${moduleData.details?.activeApp || "Unknown"}`,
          });
        }
      }

      // Handle notification violations
      if (
        module === "notification-blocker" &&
        moduleData &&
        moduleData.eventType === "violation"
      ) {
        violations.push({
          id: `notification-${timestamp}`,
          module,
          timestamp,
          deviceName: "Notification System",
          violationType: "notification-violation",
          severity: "HIGH",
          reason: "Notification settings modified during exam",
          evidence: `Type: ${moduleData.violationType || "Settings changed"}`,
        });
      }
    });

    return violations;
  }, []);

  // Update violations when module data changes
  useEffect(() => {
    const newViolations = extractViolations(moduleData);

    // Update active violations
    setActiveViolations(newViolations);

    // Add new violations to history (avoid duplicates by ID)
    if (newViolations.length > 0) {
      setViolationHistory((prev) => {
        const existingIds = new Set(prev.map((v) => v.id));
        const uniqueNewViolations = newViolations.filter(
          (v) => !existingIds.has(v.id)
        );

        if (uniqueNewViolations.length > 0) {
          setLastViolationTime(Date.now());
          return [...prev, ...uniqueNewViolations].sort(
            (a, b) => b.timestamp - a.timestamp
          );
        }

        return prev;
      });
    }
  }, [moduleData, extractViolations]);

  // Add exam exit violation if applicable
  useEffect(() => {
    if (examExited && examExitReason) {
      const exitViolation = {
        id: `exam-exit-${Date.now()}`,
        module: "system",
        timestamp: Date.now(),
        deviceName: "Exam Session",
        violationType: "exam-exit",
        severity: "CRITICAL",
        reason: examExitReason,
        evidence: "Exam session terminated",
      };

      setViolationHistory((prev) => {
        const exists = prev.some((v) => v.violationType === "exam-exit");
        if (!exists) {
          return [exitViolation, ...prev];
        }
        return prev;
      });

      setActiveViolations((prev) => {
        const exists = prev.some((v) => v.violationType === "exam-exit");
        if (!exists) {
          return [exitViolation, ...prev];
        }
        return prev;
      });
    }
  }, [examExited, examExitReason]);

  // Export violation history
  const exportViolationHistory = useCallback(() => {
    const exportData = {
      exportTime: new Date().toISOString(),
      examSession: {
        startTime:
          violationHistory.length > 0
            ? new Date(
                Math.min(...violationHistory.map((v) => v.timestamp))
              ).toISOString()
            : null,
        endTime: new Date().toISOString(),
        totalViolations: violationHistory.length,
        examExited,
        examExitReason,
      },
      violations: violationHistory.map((violation) => ({
        timestamp: new Date(violation.timestamp).toISOString(),
        module: violation.module,
        deviceName: violation.deviceName,
        violationType: violation.violationType,
        severity: violation.severity,
        reason: violation.reason,
        evidence: violation.evidence,
      })),
      violationSummary: {
        critical: violationHistory.filter((v) => v.severity === "CRITICAL")
          .length,
        high: violationHistory.filter((v) => v.severity === "HIGH").length,
        medium: violationHistory.filter((v) => v.severity === "MEDIUM").length,
        low: violationHistory.filter((v) => v.severity === "LOW").length,
      },
    };

    // Download as JSON file
    const blob = new Blob([JSON.stringify(exportData, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `exam-violations-${new Date().toISOString().split("T")[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, [violationHistory, examExited, examExitReason]);

  const getSeverityColor = (severity) => {
    switch (severity?.toUpperCase()) {
      case "CRITICAL":
        return "#e74c3c";
      case "HIGH":
        return "#e67e22";
      case "MEDIUM":
        return "#f39c12";
      case "LOW":
        return "#95a5a6";
      default:
        return "#95a5a6";
    }
  };

  const formatTime = (timestamp) => {
    return new Date(timestamp).toLocaleTimeString();
  };

  const getModuleIcon = (module) => {
    const icons = {
      "process-watch": "🔍",
      "device-watch": "💾",
      "screen-watch": "🖥️",
      "notification-blocker": "🔕",
      "vm-detect": "🖴",
      "clipboard-worker": "📋",
      "focus-idle-watch": "🎯",
      system: "⚠️",
    };
    return icons[module] || "❓";
  };

  // Don't render if no violations
  if (activeViolations.length === 0 && violationHistory.length === 0) {
    return null;
  }

  return (
    <div className="violations-banner">
      {/* Main Banner */}
      <div
        className={`violations-header ${activeViolations.length > 0 ? "has-active" : "history-only"}`}
      >
        <div className="violations-summary">
          <div className="violations-icon">
            {activeViolations.length > 0 ? "🚨" : "📊"}
          </div>
          <div className="violations-info">
            <div className="violations-title">
              {activeViolations.length > 0
                ? "ACTIVE VIOLATIONS DETECTED"
                : "VIOLATION HISTORY"}
            </div>
            <div className="violations-stats">
              <span className="active-count">
                Active: {activeViolations.length - 1}
              </span>
              <span className="history-count">
                Total: {violationHistory.length}
              </span>
              {lastViolationTime && (
                <span className="last-violation">
                  Last: {formatTime(lastViolationTime)}
                </span>
              )}
            </div>
          </div>
        </div>

        <div className="violations-actions">
          <button
            className="expand-btn"
            onClick={() => setIsExpanded(!isExpanded)}
            title={isExpanded ? "Collapse details" : "Expand details"}
          >
            {isExpanded ? "▼" : "▶"} Details
          </button>
          <button
            className="export-btn"
            onClick={exportViolationHistory}
            title="Export violation history"
            disabled={violationHistory.length === 0}
          >
            📥 Export
          </button>
        </div>
      </div>

      {/* Expanded Details */}
      {isExpanded && (
        <div className="violations-details">
          {/* Active Violations */}
          {/* {activeViolations.length > 0 && (
            <div className="violations-section">
              <AllViolationsTable
                violations={activeViolations}
                title="🚨 Active Violations"
              />
            </div>
          )} */}

          {/* Violation History */}
          {violationHistory.length > 0 && (
            <div className="violations-section">
              <h4>📊 Violation History ({violationHistory.length})</h4>
              <div className="violations-list">
                {violationHistory.slice(0, 20).map((violation) => (
                  <div
                    key={violation.id}
                    className="violation-item historical"
                    style={{
                      borderLeftColor: getSeverityColor(violation.severity),
                    }}
                  >
                    <div className="violation-header">
                      <span className="violation-module">
                        {getModuleIcon(violation.module)} {violation.module}
                      </span>
                      <span
                        className="violation-severity"
                        style={{
                          backgroundColor: getSeverityColor(violation.severity),
                        }}
                      >
                        {violation.severity}
                      </span>
                      <span className="violation-time">
                        {formatTime(violation.timestamp)}
                      </span>
                    </div>
                    <div className="violation-content">
                      <div className="violation-reason">{violation.reason}</div>
                      {violation.evidence && (
                        <div className="violation-evidence">
                          {violation.evidence}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
                {violationHistory.length > 20 && (
                  <div className="more-violations">
                    +{violationHistory.length - 20} more historical violations
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default ViolationsBanner;
