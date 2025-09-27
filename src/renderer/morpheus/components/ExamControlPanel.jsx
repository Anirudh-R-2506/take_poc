import React, { useState, useEffect } from 'react';
import examAPI from '../ExamControlAPI';
import PermissionStatusBadges from './PermissionStatusBadges';

/**
 * ExamControlPanel - Example component demonstrating exam flow
 * Shows how to use the new stopWorkers functionality
 */
const ExamControlPanel = () => {
    const [examState, setExamState] = useState('pre-assessment'); // 'pre-assessment' | 'exam-active' | 'exam-ended'
    const [permissionStatus, setPermissionStatus] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const [violations, setViolations] = useState([]);
    const [examStartTime, setExamStartTime] = useState(null);

    // Check permissions on component mount
    useEffect(() => {
        checkPermissions();
    }, []);

    // Setup violation monitoring when exam starts
    useEffect(() => {
        let unsubscribe = null;

        if (examState === 'exam-active') {
            // Subscribe to violations from ALL workers
            unsubscribe = examAPI.onViolation((violationData) => {
                if (violationData.isViolation) {
                    setViolations(prev => [...prev, {
                        id: Date.now(),
                        timestamp: violationData.timestamp,
                        module: violationData.module,
                        description: violationData.description,
                        threatLevel: violationData.threatLevel,
                        payload: violationData.payload
                    }]);
                }
            });
        }

        return () => {
            if (unsubscribe) {
                unsubscribe();
            }
        };
    }, [examState]);

    const checkPermissions = async () => {
        setIsLoading(true);
        try {
            const status = await examAPI.checkPermissions();
            setPermissionStatus(status);
        } catch (error) {
            console.error('Failed to check permissions:', error);
        } finally {
            setIsLoading(false);
        }
    };

    const requestPermission = async (permissionType) => {
        setIsLoading(true);
        try {
            await examAPI.requestPermission(permissionType);
            // Refresh permissions after request
            await checkPermissions();
        } catch (error) {
            console.error('Failed to request permission:', error);
        } finally {
            setIsLoading(false);
        }
    };

    const startExam = async () => {
        setIsLoading(true);
        try {
            const success = await examAPI.startExamMonitoring();
            if (success) {
                setExamState('exam-active');
                setExamStartTime(Date.now());
                setViolations([]); // Clear any previous violations
                console.log('✅ Exam monitoring started successfully');
            } else {
                console.error('❌ Failed to start exam monitoring');
                alert('Failed to start exam monitoring. Please check permissions.');
            }
        } catch (error) {
            console.error('Error starting exam:', error);
            alert('Error starting exam monitoring');
        } finally {
            setIsLoading(false);
        }
    };

    const endExam = async () => {
        setIsLoading(true);
        try {
            const success = await examAPI.stopExamMonitoring();
            if (success) {
                setExamState('exam-ended');
                console.log('✅ Exam monitoring stopped successfully');
            } else {
                console.error('❌ Failed to stop exam monitoring');
                alert('Failed to stop exam monitoring');
            }
        } catch (error) {
            console.error('Error stopping exam:', error);
            alert('Error stopping exam monitoring');
        } finally {
            setIsLoading(false);
        }
    };

    const resetExam = () => {
        setExamState('pre-assessment');
        setViolations([]);
        setExamStartTime(null);
        checkPermissions();
    };

    const formatTime = (timestamp) => {
        return new Date(timestamp).toLocaleTimeString();
    };

    const getThreatColor = (level) => {
        switch (level) {
            case 'critical': return '#e74c3c';
            case 'high': return '#e67e22';
            case 'medium': return '#f39c12';
            case 'low': return '#95a5a6';
            default: return '#bdc3c7';
        }
    };

    return (
        <div style={{ padding: '20px', maxWidth: '800px', margin: '0 auto' }}>
            <h1>🎓 Exam Control Panel</h1>
            <p>Demonstrates the complete exam flow with worker start/stop functionality</p>

            {/* Current State Indicator */}
            <div style={{
                padding: '10px',
                marginBottom: '20px',
                borderRadius: '5px',
                backgroundColor: examState === 'exam-active' ? '#e8f5e8' :
                               examState === 'exam-ended' ? '#fff3cd' : '#f8f9fa',
                border: `1px solid ${examState === 'exam-active' ? '#d4edda' :
                                   examState === 'exam-ended' ? '#ffeaa7' : '#e9ecef'}`
            }}>
                <strong>Current State: </strong>
                <span style={{
                    color: examState === 'exam-active' ? '#155724' :
                           examState === 'exam-ended' ? '#856404' : '#495057'
                }}>
                    {examState === 'pre-assessment' && '🔍 Pre-Assessment'}
                    {examState === 'exam-active' && '🔴 Exam Active'}
                    {examState === 'exam-ended' && '✅ Exam Ended'}
                </span>
                {examStartTime && (
                    <span style={{ marginLeft: '20px', fontSize: '0.9em', color: '#666' }}>
                        Started: {formatTime(examStartTime)}
                    </span>
                )}
            </div>

            {/* Pre-Assessment Screen */}
            {examState === 'pre-assessment' && (
                <div>
                    <h2>📋 Pre-Assessment Checklist</h2>

                    <PermissionStatusBadges
                        permissionStatus={permissionStatus}
                        onRequestPermission={requestPermission}
                        onRefreshPermissions={checkPermissions}
                        isChecking={isLoading}
                    />

                    <div style={{ marginTop: '20px' }}>
                        <button
                            onClick={startExam}
                            disabled={!permissionStatus?.allGranted || isLoading}
                            style={{
                                padding: '12px 24px',
                                fontSize: '16px',
                                fontWeight: 'bold',
                                backgroundColor: permissionStatus?.allGranted ? '#28a745' : '#6c757d',
                                color: 'white',
                                border: 'none',
                                borderRadius: '5px',
                                cursor: permissionStatus?.allGranted ? 'pointer' : 'not-allowed',
                                opacity: isLoading ? 0.7 : 1
                            }}
                        >
                            {isLoading ? '⏳ Starting...' : '🚀 Start Exam'}
                        </button>

                        {!permissionStatus?.allGranted && (
                            <p style={{ color: '#dc3545', marginTop: '10px' }}>
                                ⚠️ All permissions must be granted before starting the exam
                            </p>
                        )}
                    </div>
                </div>
            )}

            {/* Exam Active Screen */}
            {examState === 'exam-active' && (
                <div>
                    <h2>🔴 Exam in Progress</h2>
                    <p>Monitoring is active. All workers are running and detecting violations.</p>

                    {/* Violations Display */}
                    <div style={{ marginBottom: '20px' }}>
                        <h3>⚠️ Violations Detected: {violations.length}</h3>

                        {violations.length === 0 ? (
                            <div style={{
                                padding: '15px',
                                backgroundColor: '#d1edff',
                                borderRadius: '5px',
                                color: '#0c5460'
                            }}>
                                ✅ No violations detected - exam proceeding normally
                            </div>
                        ) : (
                            <div style={{
                                maxHeight: '300px',
                                overflowY: 'auto',
                                border: '1px solid #ddd',
                                borderRadius: '5px',
                                padding: '10px'
                            }}>
                                {violations.map(violation => (
                                    <div key={violation.id} style={{
                                        padding: '10px',
                                        marginBottom: '10px',
                                        border: `1px solid ${getThreatColor(violation.threatLevel)}`,
                                        borderRadius: '3px',
                                        backgroundColor: '#fff'
                                    }}>
                                        <div style={{
                                            display: 'flex',
                                            justifyContent: 'space-between',
                                            alignItems: 'center'
                                        }}>
                                            <strong>{violation.module}</strong>
                                            <span style={{
                                                color: getThreatColor(violation.threatLevel),
                                                fontWeight: 'bold',
                                                fontSize: '0.8em'
                                            }}>
                                                {violation.threatLevel.toUpperCase()}
                                            </span>
                                        </div>
                                        <div>{violation.description}</div>
                                        <div style={{ fontSize: '0.8em', color: '#666' }}>
                                            {formatTime(violation.timestamp)}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>

                    <button
                        onClick={endExam}
                        disabled={isLoading}
                        style={{
                            padding: '12px 24px',
                            fontSize: '16px',
                            fontWeight: 'bold',
                            backgroundColor: '#dc3545',
                            color: 'white',
                            border: 'none',
                            borderRadius: '5px',
                            cursor: 'pointer',
                            opacity: isLoading ? 0.7 : 1
                        }}
                    >
                        {isLoading ? '⏳ Ending...' : '🛑 End Exam'}
                    </button>
                </div>
            )}

            {/* Exam Ended Screen */}
            {examState === 'exam-ended' && (
                <div>
                    <h2>✅ Exam Completed</h2>
                    <p>Monitoring has been stopped. All workers have been shut down.</p>

                    <div style={{
                        padding: '15px',
                        backgroundColor: '#f8f9fa',
                        borderRadius: '5px',
                        marginBottom: '20px'
                    }}>
                        <h4>📊 Exam Summary</h4>
                        <p><strong>Start Time:</strong> {examStartTime ? formatTime(examStartTime) : 'N/A'}</p>
                        <p><strong>End Time:</strong> {formatTime(Date.now())}</p>
                        <p><strong>Total Violations:</strong> {violations.length}</p>

                        {violations.length > 0 && (
                            <div>
                                <strong>Violation Breakdown:</strong>
                                <ul>
                                    {Object.entries(
                                        violations.reduce((acc, v) => {
                                            acc[v.module] = (acc[v.module] || 0) + 1;
                                            return acc;
                                        }, {})
                                    ).map(([module, count]) => (
                                        <li key={module}>{module}: {count} violation(s)</li>
                                    ))}
                                </ul>
                            </div>
                        )}
                    </div>

                    <button
                        onClick={resetExam}
                        style={{
                            padding: '12px 24px',
                            fontSize: '16px',
                            fontWeight: 'bold',
                            backgroundColor: '#007bff',
                            color: 'white',
                            border: 'none',
                            borderRadius: '5px',
                            cursor: 'pointer'
                        }}
                    >
                        🔄 Reset for New Exam
                    </button>
                </div>
            )}
        </div>
    );
};

export default ExamControlPanel;