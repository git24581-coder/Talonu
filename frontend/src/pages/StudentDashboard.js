import React, { useState, useEffect } from 'react';
import apiClient from '../api/client.js';
import './StudentDashboard.css';
import './SharedRoleTabs.css';

function StudentDashboard() {
  const [attendance, setAttendance] = useState([]);
  const [vouchers, setVouchers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState(null);
  const [stats, setStats] = useState(null);
  const [activeTab, setActiveTab] = useState('attendance');
  
  // QR Code blur/enlarge state
  const [qrState, setQrState] = useState({}); // { voucherId: 'blurred' | 'clear' | 'enlarged' }

  const VOUCHER_EXPIRY_HOURS = 9;

  // Helper: check if voucher is expired (VOUCHER_EXPIRY_HOURS from issuance)
  const isVoucherExpiredByIssuedAt = (voucher) => {
    if (!voucher || !voucher.issued_at) return false;
    const issuedTime = new Date(voucher.issued_at);
    const currentTime = new Date();
    const hoursElapsed = (currentTime - issuedTime) / (1000 * 60 * 60);
    return hoursElapsed > VOUCHER_EXPIRY_HOURS;
  };

  // Helper: get remaining time for voucher (in minutes or hours)
  const getVoucherTimeRemaining = (voucher) => {
    if (!voucher || !voucher.issued_at) return null;
    const issuedTime = new Date(voucher.issued_at);
    const expiryTime = new Date(issuedTime.getTime() + VOUCHER_EXPIRY_HOURS * 60 * 60 * 1000);
    const currentTime = new Date();
    const minutesRemaining = Math.round((expiryTime - currentTime) / (1000 * 60));
    
    if (minutesRemaining < 0) return '❌ Строк дії минув';
    if (minutesRemaining < 60) return `${minutesRemaining} хв`;
    const hoursRemaining = Math.round(minutesRemaining / 60);
    return `${hoursRemaining} год`;
  };

  useEffect(() => {
    setLoading(true);
    Promise.all([fetchAttendance(), fetchVouchers()]).finally(() => {
      setLoading(false);
    });
  }, []);

  const fetchAttendance = async () => {
    try {
      // Get attendance summary
      const resp = await apiClient.get('/api/student/me/attendance-summary');
      setStats(resp.data);
      
      // Get attendance records
      const records = await apiClient.get('/api/student/me/attendance');
      setAttendance(records.data?.records || []);
    } catch (err) {
      setMessage({ 
        type: 'error', 
        text: err.response?.data?.error || 'Помилка завантаження даних присутності' 
      });
    }
  };

  const fetchVouchers = async () => {
    try {
      const resp = await apiClient.get('/api/vouchers/my');
      setVouchers(resp.data || []);
      // Initialize QR state for all vouchers as 'blurred'
      const initState = {};
      (resp.data || []).forEach(v => {
        initState[v.id] = 'blurred';
      });
      setQrState(initState);
    } catch (err) {
      console.error('Error fetching vouchers:', err);
      setVouchers([]);
    }
  };

  const toggleQrState = (voucherId) => {
    setQrState(prev => {
      const current = prev[voucherId] || 'blurred';
      let next = 'blurred';
      
      if (current === 'blurred') {
        next = 'clear';
      } else if (current === 'clear') {
        next = 'enlarged';
      } else if (current === 'enlarged') {
        next = 'blurred';
      }
      
      return { ...prev, [voucherId]: next };
    });
  };

  const getStatusColor = (status) => {
    switch(status) {
      case 'present': return '#28a745';
      case 'absent': return '#dc3545';
      default: return '#6c757d';
    }
  };

  const getStatusText = (status) => {
    const statuses = {
      'present': '✓ Присутній',
      'absent': '✗ Відсутній'
    };
    return statuses[status] || status;
  };

  return (
    <div className="student-container">
      {message && <div className={`alert alert-${message.type}`}>{message.text}</div>}

      {loading ? (
        <div className="loading">Завантаження...</div>
      ) : (
        <>
          <div className="admin-tabs">
            <button 
              className={`tab-button ${activeTab === 'attendance' ? 'active' : ''}`}
              onClick={() => setActiveTab('attendance')}
              title="Переглянути статистику вашої присутності"
            >
              📋 Присутність
            </button>
            <button 
              className={`tab-button ${activeTab === 'vouchers' ? 'active' : ''}`}
              onClick={() => setActiveTab('vouchers')}
              title="Переглянути ваші талони на їжу з QR-кодами"
            >
              🎫 Мої талони ({vouchers.length})
            </button>
          </div>

          {activeTab === 'attendance' && (
            <div className="tab-content shared-tab-content">
              {stats && (
                <div className="card" style={{marginBottom: '20px'}}>
                  <h3>📊 Статистика присутності</h3>
                  <div className="student-stats-grid">
                    <div style={{textAlign: 'center'}}>
                      <div style={{fontSize: '24px', fontWeight: 'bold', color: '#28a745'}}>
                        {stats.present || 0}
                      </div>
                      <div>✓ Присутні</div>
                    </div>
                    <div style={{textAlign: 'center'}}>
                      <div style={{fontSize: '24px', fontWeight: 'bold', color: '#dc3545'}}>
                        {stats.absent || 0}
                      </div>
                      <div>✗ Відсутні</div>
                    </div>
                    <div style={{textAlign: 'center'}}>
                      <div style={{fontSize: '24px', fontWeight: 'bold', color: '#007bff'}}>
                        {(stats.percentage || 0).toFixed(1)}%
                      </div>
                      <div>Присутність</div>
                    </div>
                  </div>
                </div>
              )}

              <div className="card">
                <h3>📅 Облік присутності</h3>
                {attendance.length === 0 ? (
                  <div className="alert alert-info">
                    Записи про присутність відсутні
                  </div>
                ) : (
                  <div className="table-scroll">
                    <table style={{ width: '100%', borderCollapse: 'collapse', boxSizing: 'border-box' }}>
                      <thead>
                        <tr style={{backgroundColor: '#f8f9fa'}}>
                          <th style={{padding: '10px', textAlign: 'left', borderBottom: '2px solid #dee2e6'}}>Дата</th>
                          <th style={{padding: '10px', textAlign: 'left', borderBottom: '2px solid #dee2e6'}}>Статус</th>
                          <th style={{padding: '10px', textAlign: 'left', borderBottom: '2px solid #dee2e6'}}>Клас</th>
                        </tr>
                      </thead>
                      <tbody>
                        {attendance.map((rec, i) => (
                          <tr key={i} style={{borderBottom: '1px solid #dee2e6'}}>
                            <td style={{padding: '10px'}}><strong>{rec.date}</strong></td>
                            <td style={{padding: '10px', color: getStatusColor(rec.status), fontWeight: 'bold'}}>
                              {getStatusText(rec.status)}
                            </td>
                            <td style={{padding: '10px'}}>{rec.class || '-'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          )}

          {activeTab === 'vouchers' && (
            <div className="tab-content shared-tab-content">
              <div style={{
                backgroundColor: '#e7f3ff',
                border: '1px solid #b3d9ff',
                borderRadius: '5px',
                padding: '12px',
                marginBottom: '20px',
                fontSize: '13px',
                color: '#004085'
              }}>
                💡 <strong>Як використовувати талон:</strong>
                <ol style={{ margin: '8px 0 0 0', paddingLeft: '20px' }}>
                  <li>Натисніть на талон нижче, щоб показати QR-код</li>
                  <li>Покажіть QR-код касирові на касі</li>
                  <li>Касир відсканує ваш QR-код камерою</li>
                  <li>✓ Готово! Вам буде видано їжу</li>
                </ol>
              </div>

              {vouchers.length === 0 ? (
                <div className="card">
                  <div className="alert alert-info">
                    📭 У вас немає талонів. Талони видаються автоматично о 09:15
                  </div>
                </div>
              ) : (
                <div className="student-voucher-grid">
                  {vouchers.map(voucher => {
                    const state = qrState[voucher.id] || 'blurred';
                    const isBlurred = state === 'blurred';
                    const isEnlarged = state === 'enlarged';
                    const isCompactViewport = typeof window !== 'undefined' && window.matchMedia('(max-width: 768px)').matches;
                    const isUsedVoucher = Boolean(
                      voucher.isUsed ||
                      voucher.usedToday ||
                      Number(voucher.current_uses || 0) >= Number(voucher.max_uses || 1)
                    );
                    const isExpiredByTime = !isUsedVoucher && isVoucherExpiredByIssuedAt(voucher);
                    const isExpiredVoucher = !isUsedVoucher && (isExpiredByTime || Boolean(voucher.isExpired));
                    const isInactiveVoucher = isUsedVoucher || isExpiredVoucher;

                    let voucherStatusText = '✅ Активний';
                    if (isUsedVoucher) {
                      voucherStatusText = '✅ Використано';
                    } else if (isExpiredByTime) {
                      voucherStatusText = `⏰ Строк дії минув (${VOUCHER_EXPIRY_HOURS} год)`;
                    } else if (isExpiredVoucher) {
                      voucherStatusText = '❌ Строк дії минув';
                    }

                    return (
                      <div key={voucher.id} className="card" style={{ 
                        padding: '15px', 
                        position: 'relative', 
                        overflow: 'hidden',
                        borderTop: isInactiveVoucher ? '5px solid #c62828' : '5px solid #2e7d32',
                        backgroundColor: isInactiveVoucher ? '#ffebee' : '#ffffff',
                        borderRadius: '8px',
                        boxShadow: isInactiveVoucher ? '0 4px 12px rgba(198, 40, 40, 0.15)' : '0 2px 8px rgba(0, 0, 0, 0.08)'
                      }}>
                        <h4 style={{ marginTop: 0, marginBottom: '10px', color: isInactiveVoucher ? '#c62828' : '#2c3e50' }}>
                          {'\uD83C\uDFAB'} {voucher.student_name}
                        </h4>
                        
                        <div style={{ marginBottom: '10px' }}>
                          <small style={{ color: isInactiveVoucher ? '#c62828' : '#666' }}>
                            <strong>{'\u0414\u0430\u0442\u0430 \u0432\u0438\u0434\u0430\u0447\u0456:'}</strong> {voucher.created_date || '-'}
                          </small><br/>
                          {!isUsedVoucher && !isExpiredVoucher && voucher.issued_at && (
                            <small style={{ 
                              color: '#2e7d32',
                              fontWeight: 'bold',
                              fontSize: '12px',
                              display: 'block',
                              marginTop: '3px'
                            }}>
                              {'\uD83D\uDD50'} {getVoucherTimeRemaining(voucher)}
                            </small>
                          )}
                          {!isUsedVoucher && isExpiredByTime && (
                            <small style={{ 
                              color: '#c62828',
                              fontWeight: 'bold',
                              fontSize: '12px',
                              display: 'block',
                              marginTop: '3px'
                            }}>
                              ⏰ Строк дії талона минув
                            </small>
                          )}
                          <small style={{
                            color: isInactiveVoucher ? '#c62828' : '#2e7d32',
                            fontWeight: 'bold',
                            fontSize: '14px'
                          }}>
                            <strong>{'\u0421\u0442\u0430\u0442\u0443\u0441:'}</strong> {voucherStatusText}
                          </small><br/>
                          <small style={{ color: isInactiveVoucher ? '#c62828' : '#666' }}>
                            <strong>{'\u0412\u0438\u043a\u043e\u0440\u0438\u0441\u0442\u0430\u043d\u044c:'}</strong> {voucher.current_uses}/{voucher.max_uses}
                          </small>
                        </div>

                        <div
                          title="Натисніть, щоб показати або приховати QR-код. Касир відсканує цей код"
                          style={{
                          marginTop: '15px',
                          marginBottom: '10px',
                          textAlign: 'center',
                          padding: isCompactViewport ? '14px 10px' : '20px 15px',
                          backgroundColor: '#f5f5f5',
                          borderRadius: '12px',
                          cursor: 'pointer',
                          transition: 'all 0.5s cubic-bezier(0.34, 1.56, 0.64, 1)',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          boxShadow: isEnlarged ? '0 10px 30px rgba(0,0,0,0.15)' : '0 2px 8px rgba(0,0,0,0.08)',
                          transform: isEnlarged ? (isCompactViewport ? 'scale(1.04)' : 'scale(1.3)') : 'scale(1)',
                          minHeight: isEnlarged ? (isCompactViewport ? '300px' : '450px') : (isCompactViewport ? '200px' : '240px')
                        }}
                          onClick={() => toggleQrState(voucher.id)}
                        >
                          {voucher.qrImage ? (
                            <div style={{
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              transition: 'all 0.5s cubic-bezier(0.34, 1.56, 0.64, 1)',
                              width: isCompactViewport ? 'min(170px, 72vw)' : '200px',
                              height: isCompactViewport ? 'min(170px, 72vw)' : '200px',
                              maxWidth: '100%'
                            }}>
                              <img 
                                src={voucher.qrImage} 
                                alt="QR Code" 
                                style={{
                                  width: '100%',
                                  height: '100%',
                                  objectFit: 'cover',
                                  filter: isBlurred ? 'blur(12px)' : 'blur(0px)',
                                  transition: 'filter 0.5s ease-in-out',
                                  borderRadius: '8px'
                                }}
                              />
                            </div>
                          ) : (
                            <div style={{ color: '#999', padding: '40px' }}>
                              Немає QR-коду
                            </div>
                          )}
                        </div>

                        <div style={{ fontSize: '12px', color: '#666', textAlign: 'center', padding: '10px', backgroundColor: '#f0f0f0', borderRadius: '4px' }}>
                          {isBlurred && '👆 Натисни, щоб показати'}
                          {!isBlurred && isEnlarged && '👆 Натисни, щоб приховати'}
                          {!isBlurred && !isEnlarged && '👆 Натисни, щоб збільшити'}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}

export default StudentDashboard;

