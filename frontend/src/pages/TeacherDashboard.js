import React, { useState, useEffect, useCallback } from 'react';
import apiClient from '../api/client.js';
import './TeacherDashboard.css';
import './SharedRoleTabs.css';

function TeacherDashboard() {
  const [activeTab, setActiveTab] = useState('attendance');
  const [students, setStudents] = useState([]);
  const [message, setMessage] = useState(null);
  const [loading, setLoading] = useState(true);
  const [classInfo, setClassInfo] = useState(null);
  const [attendanceRecords, setAttendanceRecords] = useState([]);
  const [attendanceMap, setAttendanceMap] = useState({});
  const [savingStates, setSavingStates] = useState({});

  const markAllPresent = async () => {
    try {
      const userIds = students.map(s => s.id);
      for (const studentId of userIds) {
        await apiClient.post('/api/users/attendance/set', { userIds: [studentId] });
      }
      setAttendanceMap(prev => {
        const newMap = { ...prev };
        userIds.forEach(id => {
          newMap[id] = true;
        });
        return newMap;
      });
      setMessage({ type: 'success', text: 'Всі учні позначені як присутні' });
    } catch (e) {
      setMessage({ type: 'error', text: e.response?.data?.error || 'Помилка' });
    }
  };

  const load = useCallback(async () => {
    setLoading(true);
    try {
      // Get my students with their attendance status for today in ONE query
      const resp = await apiClient.get('/api/teachers/my-students');
      const studentsData = resp.data || [];
      setStudents(studentsData);
      
      // Build attendance map from response
      const map = {};
      studentsData.forEach(student => {
        if (student.status === 'present') {
          map[student.id] = true;
        }
      });
      setAttendanceMap(map);
      
      // Get my classes info
      try {
        const classResp = await apiClient.get('/api/teacher/my-classes');
        if (classResp.data && classResp.data.length > 0) {
          setClassInfo(classResp.data[0]);
        }
      } catch (e) {
        console.log('Could not load class info');
      }
    } catch (e) {
      setMessage({ type: 'error', text: e.response?.data?.error || 'Не вдалося завантажити учнів' });
    }
    setLoading(false);
  }, []);

  const loadAttendanceRecords = useCallback(async () => {
    try {
      const resp = await apiClient.get('/api/users/attendance');
      setAttendanceRecords(resp.data || []);
    } catch (e) {
      console.log('Could not load attendance records');
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (activeTab === 'records') {
      loadAttendanceRecords();
    }
  }, [activeTab, loadAttendanceRecords]);

  const togglePresence = async (studentId) => {
    const isCurrentlyPresent = attendanceMap[studentId];
    
    setSavingStates(prev => ({ ...prev, [studentId]: true }));
    
    try {
      if (isCurrentlyPresent) {
        await apiClient.post('/api/users/attendance/unset', { userIds: [studentId] });
      } else {
        await apiClient.post('/api/users/attendance/set', { userIds: [studentId] });
      }
      
      setAttendanceMap(prev => ({
        ...prev,
        [studentId]: !isCurrentlyPresent
      }));
    } catch (e) {
      setMessage({ type: 'error', text: e.response?.data?.error || 'Помилка при позначенні' });
    } finally {
      setSavingStates(prev => ({ ...prev, [studentId]: false }));
    }
  };

  if (loading) {
    return <div className="container"><div className="loading">Завантаження...</div></div>;
  }

  return (
    <div className="container">
      <div className="teacher-header">
        <h1>👩‍🏫 Мій клас</h1>
        {classInfo && <p style={{color: '#666', marginTop: 5}}>Клас: <strong>{classInfo.name}</strong> ({classInfo.student_count} учнів)</p>}
      </div>

      {message && <div className={`alert alert-${message.type}`}>{message.text}</div>}

      {/* Tabs */}
      <div>
        <div className="admin-tabs">
          <button 
            className={`tab-button ${activeTab === 'attendance' ? 'active' : ''}`}
            onClick={() => setActiveTab('attendance')}
            title="Позначте присутність учнів вашого класу. Натисніть на учня, щоб позначити або скасувати позначення"
          >
            📋 Позначення присутності
          </button>
          <button 
            className={`tab-button ${activeTab === 'records' ? 'active' : ''}`}
            onClick={() => setActiveTab('records')}
            title="Переглянути історію присутності учнів за всі дні"
          >
            📅 Облік присутності
          </button>
        </div>

        {/* Attendance Tab */}
        {activeTab === 'attendance' && (
          <div className="tab-content shared-tab-content">
            {students.length === 0 ? (
              <div className="alert alert-info">Учнів не знайдено</div>
            ) : (
              <div>
                <button
                  className="btn-success teacher-mark-all-btn"
                  onClick={markAllPresent}
                  title="Позначити всіх учнів як присутніх одним кліком"
                >
                  ✓✓ Позначити всіх учнів присутніми
                </button>

                <div className="table-scroll teacher-table-scroll" style={{ marginBottom: '15px' }}>
                  <table style={{width: '100%', borderCollapse: 'collapse', fontSize: '14px', boxSizing: 'border-box'}}>
                    <thead>
                      <tr style={{backgroundColor: '#007bff', color: '#fff', borderBottom: '2px solid #0056b3'}}>
                        <th style={{padding: '12px', textAlign: 'left', fontWeight: 'bold'}}>Прізвище, Ім'я</th>
                        <th style={{padding: '8px 6px', textAlign: 'center', fontWeight: 'bold', backgroundColor: '#0056b3'}}>Статус</th>
                      </tr>
                    </thead>
                    <tbody>
                      {students.map((student, idx) => {
                        const isPresent = attendanceMap[student.id];
                        const isSaving = savingStates[student.id];
                        
                        return (
                          <tr key={student.id} style={{borderBottom: '1px solid #e0e0e0', backgroundColor: idx % 2 === 0 ? '#fff' : '#f9f9f9'}}>
                            <td style={{padding: '12px', fontWeight: 'bold', color: '#333'}}>{student.name}</td>
                            <td 
                              title={isPresent ? "Натисніть, щоб позначити як відсутнього" : "Натисніть, щоб позначити як присутнього"}
                              style={{
                                padding: '8px 6px',
                                textAlign: 'center',
                                cursor: isSaving ? 'not-allowed' : 'pointer',
                                backgroundColor: isPresent ? '#c8e6c9' : '#ffebee',
                                transition: 'all 0.2s',
                                opacity: isSaving ? 0.7 : 1
                              }}
                              onClick={() => !isSaving && togglePresence(student.id)}
                            >
                              {isSaving ? (
                                <span style={{opacity: 0.5}}>⏳</span>
                              ) : isPresent ? (
                                <span className="attendance-status-pill" style={{ color: '#28a745' }}>✓ Присутній</span>
                              ) : (
                                <span className="attendance-status-pill" style={{ color: '#ccc' }}>○ Відсутній</span>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
            <div className="teacher-hint-box" style={{marginTop: '15px', padding: '10px', backgroundColor: '#f0f8ff', borderRadius: '6px', fontSize: '13px', color: '#555'}}>
              💡 <strong>Як користуватися:</strong> 
              <br/>• Натисніть на учня, щоб позначити його як <strong>присутнього</strong> або <strong>відсутнього</strong>
              <br/>• Учні позначені як присутні отримають талон о 09:15
            </div>
          </div>
        )}

        {/* Records Tab */}
        {activeTab === 'records' && (
          <div className="tab-content shared-tab-content">
            {attendanceRecords.length === 0 ? (
              <div className="alert alert-info">Записи про присутність відсутні</div>
            ) : (
              <div className="table-scroll teacher-table-scroll">
                <table style={{width: '100%', borderCollapse: 'collapse', boxSizing: 'border-box'}}>
                  <thead>
                    <tr style={{backgroundColor: '#f8f9fa', borderBottom: '2px solid #dee2e6'}}>
                      <th style={{padding: '10px', textAlign: 'left'}}>Учень</th>
                      <th style={{padding: '10px', textAlign: 'left'}}>Присутність</th>
                      <th style={{padding: '10px', textAlign: 'left'}}>Дата</th>
                    </tr>
                  </thead>
                  <tbody>
                    {attendanceRecords.map((rec, i) => (
                      <tr key={i} style={{borderBottom: '1px solid #e0e0e0'}}>
                        <td style={{padding: '10px'}}><strong>{rec.name}</strong></td>
                        <td style={{
                          padding: '10px',
                          color: rec.status === 'present' ? '#28a745' : '#dc3545',
                          fontWeight: 'bold'
                        }}>
                          {rec.status === 'present' ? '✓ Присутній' : '✗ Відсутній'}
                        </td>
                        <td style={{padding: '10px', color: '#666'}}>{rec.attendance_date || new Date().toLocaleDateString('uk-UA')}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default TeacherDashboard;
