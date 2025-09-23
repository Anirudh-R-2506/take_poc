import React from 'react';
import './PermissionStatusBadges.css';

const PermissionStatusBadges = ({
  permissionStatus,
  onRequestPermission,
  onRefreshPermissions,
  isChecking = false
}) => {
  // Don't render anything if no permission status and not checking
  if (!permissionStatus && !isChecking) {
    return (
      <div className="permission-badges">
        <div className="permission-header">
          <h3>🔐 System Permissions</h3>
          <p>Click "Check Permissions" to verify system access</p>
        </div>
      </div>
    );
  }

  // Show loading state while checking
  if (isChecking && !permissionStatus) {
    return (
      <div className="permission-badges">
        <div className="permission-header">
          <h3>🔐 System Permissions</h3>
          <p>Checking permissions...</p>
        </div>
        <div className="permission-badge checking">
          <div className="permission-main">
            <span className="permission-icon">⟳</span>
            <span className="permission-name">Checking System Permissions</span>
            <span className="permission-status">CHECKING</span>
          </div>
          <div className="permission-description">
            Verifying system access permissions...
          </div>
        </div>
      </div>
    );
  }

  // Show permission status
  if (permissionStatus && permissionStatus.permissions) {
    const getStatusColor = (status) => {
      switch (status) {
        case 'granted': return 'granted';
        case 'denied': return 'denied';
        case 'checking': return 'checking';
        default: return 'unknown';
      }
    };

    const getStatusIcon = (status) => {
      switch (status) {
        case 'granted': return '✓';
        case 'denied': return '✗';
        case 'checking': return '⟳';
        default: return '?';
      }
    };

    const missingPermissions = Object.entries(permissionStatus.permissions)
      .filter(([_, perm]) => perm.required && perm.status !== 'granted');

    return (
      <div className="permission-badges">
        <div className="permission-header">
          <h3>🔐 System Permissions</h3>
          <button
            className="refresh-permissions-btn"
            onClick={onRefreshPermissions}
            disabled={isChecking}
            title="Check permission status"
          >
            {isChecking ? '⟳ Checking...' : '⟳ Refresh'}
          </button>
        </div>

        <div className="permission-grid">
          {Object.entries(permissionStatus.permissions).map(([key, permission]) => (
            <div key={key} className={`permission-badge ${getStatusColor(permission.status)}`}>
              <div className="permission-main">
                <span className="permission-icon">{getStatusIcon(permission.status)}</span>
                <span className="permission-name">{permission.name}</span>
                <span className="permission-status">{permission.status.toUpperCase()}</span>
              </div>

              {permission.error && (
                <div className="permission-error" title={permission.error}>
                  Error: {permission.error}
                </div>
              )}

              <div className="permission-description">
                {permission.description}
              </div>

              {permission.required && permission.status !== 'granted' && (
                <button
                  className="request-permission-btn"
                  onClick={() => {
                    console.log(`[PermissionBadge] Requesting permission: ${key}`);
                    onRequestPermission(key);
                  }}
                  disabled={permission.status === 'checking' || isChecking}
                  title={`Request ${permission.name.toLowerCase()} permission`}
                >
                  {permission.status === 'checking' || isChecking ? 'Requesting...' : `Grant ${permission.name}`}
                </button>
              )}

              {permission.services && permission.services.length > 0 && (
                <div className="permission-services">
                  <small>Required by: {permission.services.join(', ')}</small>
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Status summary */}
        {permissionStatus.allGranted ? (
          <div className="permission-success">
            <strong>✅ All permissions granted!</strong>
            <span> Proctoring system is ready to start.</span>
          </div>
        ) : (
          <div className="permission-warning">
            <strong>⚠️ {missingPermissions.length} permission(s) missing</strong>
            <div style={{ marginTop: '10px' }}>
              <p><strong>To continue:</strong></p>
              <ol style={{ textAlign: 'left', marginLeft: '20px', marginTop: '5px' }}>
                <li>Click "Grant" buttons above for missing permissions</li>
                <li>Follow system prompts to enable access</li>
                <li>Click "Refresh" to verify permissions</li>
                <li>Monitoring will start automatically when all permissions are granted</li>
              </ol>
            </div>
          </div>
        )}
      </div>
    );
  }

  // Fallback
  return (
    <div className="permission-badges">
      <div className="permission-header">
        <h3>🔐 System Permissions</h3>
        <p>Permission status unavailable</p>
      </div>
    </div>
  );
};

export default PermissionStatusBadges;