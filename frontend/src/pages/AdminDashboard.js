import React, { useState, useEffect } from 'react';
/* eslint-disable react-hooks/exhaustive-deps */
import apiClient from '../api/client.js';
import QRScanner from '../components/QRScanner.js';
import AdminSettings from './AdminSettings.js';
import AdminClasses from './AdminClasses.js';
import './AdminDashboard.css';
import './AdminMobileOptimizations.css';

function AdminDashboard() {
  const [activeTab, setActiveTab] = useState('users');
  const [message, setMessage] = useState(null);
  const [loading, setLoading] = useState(false);
  const [users, setUsers] = useState([]);
  const [classesList, setClassesList] = useState([]);
  const [allVouchers, setAllVouchers] = useState([]);
  const [stats, setStats] = useState(null);
  const [searchName, setSearchName] = useState('');
  const [selectedClassFilter, setSelectedClassFilter] = useState('');
  const [confirmDelete, setConfirmDelete] = useState(null);
  const [selectedStudentProfile, setSelectedStudentProfile] = useState(null);
  const [studentVouchers, setStudentVouchers] = useState([]);

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

  // Helper to make API calls using centralized apiClient
  const apiCall = async (method, path, data = null) => {
    console.log(`🔄 apiCall(${method}, ${path})`);
    try {
      let response;
      if (method === 'GET') {
        response = await apiClient.get(path);
      } else if (method === 'POST') {
        response = await apiClient.post(path, data);
      } else if (method === 'PUT') {
        response = await apiClient.put(path, data);
      } else if (method === 'DELETE') {
        response = await apiClient.delete(path);
      }
      console.log(`✓ ${method} ${path} - Status ${response.status}`);
      return response;
    } catch (error) {
      console.error(`❌ ${method} ${path} failed:`, error.response?.status, error.response?.data?.error);
      throw error;
    }
  };

  // Fetch helpers (declared as functions so they are hoisted)
  async function fetchUsers() {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      console.log('📋 fetchUsers() called');
      console.log('  Token from localStorage:', token ? token.substring(0, 30) + '...' : 'NOT FOUND');
      
      const [usersResponse, attendanceResponse] = await Promise.all([
        apiCall('GET', '/api/users'),
        apiCall('GET', '/api/users/attendance').catch(() => ({ data: [] }))
      ]);

      const attendanceMap = new Map(
        (attendanceResponse.data || []).map((row) => [
          String(row.id),
          String(row.status || '').toLowerCase() === 'present'
        ])
      );

      const mergedUsers = (usersResponse.data || []).map((user) => {
        const fallbackPresent = Boolean(user.present);
        const resolvedPresent = user.role === 'student'
          ? (attendanceMap.has(String(user.id)) ? attendanceMap.get(String(user.id)) : fallbackPresent)
          : fallbackPresent;

        return {
          ...user,
          present: resolvedPresent
        };
      });

      setUsers(mergedUsers);
      // also attempt to load classes for admin dropdowns
      try {
        const clsResp = await apiCall('GET', '/api/classes');
        setClassesList(clsResp.data || clsResp || []);
      } catch (e) {
        // ignore
      }
      console.log('✓ Users loaded:', mergedUsers.length || 0);
    } catch (err) {
      console.error('❌ Fetch users error:', {
        status: err.response?.status,
        error: err.response?.data?.error,
        message: err.message,
        fullResponse: err.response?.data
      });
      const errorMsg = err.response?.data?.error || err.message || 'Помилка завантаження користувачів';
      setMessage({ type: 'error', text: errorMsg });
      setUsers([]);
    }
    setLoading(false);
  }

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => {
    setMessage(null);
    if (activeTab === 'vouchers') {
      fetchAllVouchers();
    } else if (activeTab === 'scan') {
      // QRScanner doesn't need specific data 
    } else if (activeTab === 'settings') {
      // AdminSettings component loads its own data
    } else if (activeTab === 'stats') {
      fetchStats();
    } else {
      fetchUsers();
    }
  }, [activeTab]);
  async function fetchStats() {
    setLoading(true);
    try {
      const response = await apiCall('GET', '/api/stats');
      setStats(response.data || {});
    } catch (err) {
      setMessage({ type: 'error', text: err.response?.data?.error || 'Помилка завантаження статистики' });
    }
    setLoading(false);
  }

  async function fetchAllVouchers() {
    setLoading(true);
    try {
      const response = await apiCall('GET', '/api/vouchers/all');
      // Деталізація дублікатів за id
      const vouchers = response.data || [];
      const uniqueVouchers = Array.from(new Map(vouchers.map(v => [v.id, v])).values());
      setAllVouchers(uniqueVouchers);
    } catch (err) {
      setMessage({ type: 'error', text: err.response?.data?.error || 'Помилка завантаження талонів' });
    }
    setLoading(false);
  }
  const handleDeleteVoucher = async (voucherId) => {
    setConfirmDelete(voucherId);
  };

  const confirmDeleteVoucher = async () => {
    if (!confirmDelete) return;
    try {
      await apiCall('DELETE', `/api/vouchers/${confirmDelete}`);
      setMessage({ type: 'success', text: 'Талон видалено' });
      setConfirmDelete(null);
      fetchAllVouchers();
    } catch (err) {
      setMessage({ type: 'error', text: err.response?.data?.error || 'Помилка видалення талону' });
      setConfirmDelete(null);
    }
  };

  const viewStudentProfile = async (student) => {
    setSelectedStudentProfile(student);
    setLoading(true);
    try {
      const response = await apiCall('GET', `/api/vouchers/user/${student.id}`);
      setStudentVouchers(response.data || []);
    } catch (err) {
      setMessage({ type: 'error', text: 'Помилка завантаження талонів учня' });
      setStudentVouchers([]);
    }
    setLoading(false);
  };

  const deleteStudentVoucher = async (voucherId) => {
    try {
      await apiCall('DELETE', `/api/vouchers/${voucherId}`);
      setMessage({ type: 'success', text: 'Талон видалено' });
      viewStudentProfile(selectedStudentProfile);
    } catch (err) {
      setMessage({ type: 'error', text: err.response?.data?.error || 'Помилка видалення' });
    }
  };

  return (
    <div className="container">

      <div className="admin-tabs">
        <button 
          className={`tab-button ${activeTab === 'users' ? 'active' : ''}`}
          onClick={() => setActiveTab('users')}
        >
          👥 Користувачі
        </button>
        <button 
          className={`tab-button ${activeTab === 'classes' ? 'active' : ''}`}
          onClick={() => setActiveTab('classes')}
          title="Управління класами, вчителями та учнями"
        >
          📚 Класи
        </button>
        <button 
          className={`tab-button ${activeTab === 'scan' ? 'active' : ''}`}
          onClick={() => setActiveTab('scan')}
          title="Сканування та перевірка QR кодів талонів"
        >
          🔍 Сканування
        </button>
        <button 
          className={`tab-button ${activeTab === 'vouchers' ? 'active' : ''}`}
          onClick={() => setActiveTab('vouchers')}
          title="Перегляд всіх видатих талонів"
        >
          🎫 Всі талони
        </button>
        <button 
          className={`tab-button ${activeTab === 'stats' ? 'active' : ''}`}
          onClick={() => setActiveTab('stats')}
          title="Статистика та метрики системи"
        >
          📊 Статистика
        </button>
        <button 
          className={`tab-button ${activeTab === 'settings' ? 'active' : ''}`}
          onClick={() => setActiveTab('settings')}
          title="Налаштування системи"
        >
          🔧 Налаштування
        </button>
      </div>

      {activeTab === 'users' && (
        <div className="tab-content">
          <div className="card">
            <h2>👥 Управління користувачами</h2>
            {message && (
              <div className={`alert alert-${message.type}`}>
                {message.text}
              </div>
            )}
            <div style={{ marginBottom: '20px' }}>
              <p style={{ color: '#666', marginBottom: '10px' }}>Всього користувачів: {users.length}</p>
              <div style={{ display: 'flex', gap: '10px', marginBottom: '10px', flexWrap: 'wrap' }}>
                <button className="btn-secondary" onClick={() => { setMessage(null); fetchUsers(); }}>
                  🔄 Оновити список
                </button>
                <button className="btn-secondary" onClick={async () => {
                  try {
                      const response = await apiCall('POST', '/api/users/attendance/clear-all', {});
                      setMessage({ type: 'success', text: `Присутність очищена для ${response.data.cleared} учнів` });
                      fetchUsers();
                  } catch (err) {
                    setMessage({ type: 'error', text: err.response?.data?.error || 'Помилка' });
                  }
                }}>
                  ✗ Очистити всіх від присутності
                </button>
              </div>
            </div>
            {loading ? (
              <div className="loading">Завантаження...</div>
            ) : users.length === 0 ? (
              <div className="alert alert-info">Користувачів не знайдено</div>
            ) : (
              <div className="responsive-table-wrap">
                <table className="users-table" style={{ width: '100%', borderCollapse: 'collapse', boxSizing: 'border-box' }}>
                  <thead>
                    <tr style={{ borderBottom: '2px solid #ddd', backgroundColor: '#f5f5f5' }}>
                      <th style={{ padding: '10px', textAlign: 'left' }}>Ім'я</th>
                      <th style={{ padding: '10px', textAlign: 'left' }}>Username</th>
                      <th style={{ padding: '10px', textAlign: 'left' }}>Роль</th>
                      <th style={{ padding: '10px', textAlign: 'left' }}>Клас</th>
                      <th style={{ padding: '10px', textAlign: 'center' }}>Присутність</th>
                      <th style={{ padding: '10px', textAlign: 'center' }}>Дія</th>
                    </tr>
                  </thead>
                  <tbody>
                    {users.map(user => (
                      <tr key={user.id} style={{ borderBottom: '1px solid #eee', backgroundColor: user.present ? '#f0f8ff' : '#fff' }}>
                        <td style={{ padding: '10px' }}>{user.name || '-'}</td>
                        <td style={{ padding: '10px' }}>{user.username}</td>
                        <td style={{ padding: '10px' }}>
                          <span style={{
                            padding: '3px 8px', 
                            borderRadius: '3px',
                            fontSize: '12px',
                            backgroundColor: user.role === 'student' ? '#e3f2fd' : user.role === 'teacher' ? '#f3e5f5' : '#e8f5e9',
                            color: user.role === 'student' ? '#1976d2' : user.role === 'teacher' ? '#7b1fa2' : '#388e3c'
                          }}>
                            {user.role === 'student' ? '👨‍🎓 Учень' : user.role === 'teacher' ? '👨‍🏫 Вчитель' : 'Касир'}
                          </span>
                        </td>
                        <td style={{ padding: '10px' }}>{user.class_id ? classesList?.find(c => c.id === user.class_id)?.name || 'N/A' : '-'}</td>
                        <td style={{ padding: '10px', textAlign: 'center' }}>
                          <span style={{
                            padding: '3px 8px',
                            borderRadius: '3px',
                            fontSize: '12px',
                            fontWeight: 'bold',
                            backgroundColor: user.present ? '#c8e6c9' : '#ffcccc',
                            color: user.present ? '#2e7d32' : '#c62828',
                            cursor: 'pointer'
                          }} title="Клік для зміни статусу" onClick={async () => {
                            try {
                                if (user.present) {
                                await apiCall('POST', '/api/users/attendance/unset', { userIds: [user.id] });
                                setMessage({ type: 'success', text: `Присутність знята для ${user.name || user.username}` });
                              } else {
                                await apiCall('POST', '/api/users/attendance/set', { userIds: [user.id] });
                                setMessage({ type: 'success', text: `Присутність позначена для ${user.name || user.username}` });
                              }
                              fetchUsers();
                            } catch (err) {
                              setMessage({ type: 'error', text: err.response?.data?.error || 'Помилка' });
                            }
                          }}>
                            {user.present ? '✓ Так' : '✗ Ні'}
                          </span>
                        </td>
                        <td style={{ padding: '10px', textAlign: 'center' }}>
                          {user.role === 'student' && (
                            <button 
                              className="btn-primary btn-small"
                              onClick={() => viewStudentProfile(user)}
                              
                              title="Переглядати профіль та талони учня"
                            >
                              📋 Профіль
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {activeTab === 'classes' && (
        <AdminClasses />
      )}

      {activeTab === 'scan' && (
        <div className="tab-content">
          <div className="scanner-card">
            <QRScanner isVisible={activeTab === 'scan'} onScan={(data) => { console.log('Voucher scanned:', data); setMessage({ type: 'success', text: `Талон від ${data.owner_name || 'невідомого'} обработано` }); }} />
          </div>
        </div>
      )}

      {activeTab === 'vouchers' && (
        <div className="tab-content">
          <div className="card">
            <h2>🎫 Всі талони</h2>
            {message && (
              <div className={`alert alert-${message.type}`}>
                {message.text}
              </div>
            )}
            <div style={{ marginBottom: '20px' }}>
              <p style={{ color: '#666', marginBottom: '10px' }}>Всього талонів: {allVouchers.length}</p>
              <button className="btn-secondary" onClick={() => fetchAllVouchers()}>
                🔄 Оновити список
              </button>
            </div>
            {loading ? (
              <div className="loading">Завантаження...</div>
            ) : allVouchers.length === 0 ? (
              <div className="alert alert-info">Талонів не знайдено</div>
            ) : (
              <div className="responsive-table-wrap">
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '14px' }}>
                  <thead>
                    <tr style={{ borderBottom: '2px solid #ddd', backgroundColor: '#f5f5f5' }}>
                      <th style={{ padding: '10px', textAlign: 'left' }}>Власник</th>
                      <th style={{ padding: '10px', textAlign: 'center' }}>Дата створення</th>
                      <th style={{ padding: '10px', textAlign: 'center' }}>Строк дії</th>
                      <th style={{ padding: '10px', textAlign: 'center' }}>Використано</th>
                      <th style={{ padding: '10px', textAlign: 'center' }}>Статус</th>
                      <th style={{ padding: '10px', textAlign: 'center' }}>Дія</th>
                    </tr>
                  </thead>
                  <tbody>
                    {allVouchers.map(voucher => {
                      const is12HourExpired = isVoucherExpiredByIssuedAt(voucher);
                      const timeRemaining = getVoucherTimeRemaining(voucher);
                      return (
                      <tr key={voucher.id} style={{ borderBottom: '1px solid #eee', backgroundColor: is12HourExpired ? '#ffebee' : 'transparent' }}>
                        <td style={{ padding: '10px' }}>{voucher.owner_name || voucher.owner_username || '-'}</td>
                        <td style={{ padding: '10px', textAlign: 'center', fontSize: '13px' }}>{voucher.created_date}</td>
                        <td style={{ padding: '10px', textAlign: 'center', fontSize: '13px' }}>
                          {voucher.expires_date ? (
                            <div>{voucher.expires_date}</div>
                          ) : (!voucher.issued_at) ? (
                            <div>{`🕐 ${VOUCHER_EXPIRY_HOURS} год`}</div>
                          ) : null}
                          <div style={{ fontSize: '11px', color: is12HourExpired ? '#c62828' : '#666', fontWeight: is12HourExpired ? 'bold' : 'normal' }}>
                            {voucher.issued_at ? (
                              <>
                                {timeRemaining === '❌ Строк дії минув' ? (
                                  <span style={{ color: '#c62828', fontWeight: 'bold' }}>❌ Строк дії минув</span>
                                ) : (
                                  <>🕐 {timeRemaining}</>
                                )}
                              </>
                            ) : (
                              <>
                                ⚠️ Немає часу видачи
                              </>
                            )}
                          </div>
                        </td>
                        <td style={{ padding: '10px', textAlign: 'center' }}>
                          <span style={{ 
                            padding: '2px 6px', 
                            borderRadius: '3px',
                            backgroundColor: voucher.current_uses >= voucher.max_uses ? '#ffcdd2' : '#e8f5e9',
                            color: voucher.current_uses >= voucher.max_uses ? '#c62828' : '#2e7d32',
                            fontSize: '12px',
                            fontWeight: 'bold'
                          }}>
                            {voucher.current_uses}/{voucher.max_uses}
                          </span>
                        </td>
                        <td style={{ padding: '10px', textAlign: 'center' }}>
                          {(() => {
                            const isFullyUsed = voucher.current_uses >= voucher.max_uses;
                            const isExp12h = isVoucherExpiredByIssuedAt(voucher);
                            return (
                              <span style={{
                                padding: '3px 8px',
                                borderRadius: '3px',
                                fontSize: '12px',
                                backgroundColor: isFullyUsed ? '#ffcdd2' : (isExp12h ? '#ffcdd2' : (voucher.status === 'active' ? '#c8e6c9' : '#fff9c4')),
                                color: isFullyUsed ? '#c62828' : (isExp12h ? '#c62828' : (voucher.status === 'active' ? '#2e7d32' : '#f57f17'))
                              }}>
                                {isFullyUsed ? '✗ Повністю використаний' : (isExp12h ? '❌ Строк дії минув' : (voucher.status === 'active' ? '✓ Активний' : 'Неактивний'))}
                              </span>
                            );
                          })()}
                        </td>
                        <td style={{ padding: '10px', textAlign: 'center' }}>
                          <button 
                            className="btn-danger btn-small"
                            onClick={() => handleDeleteVoucher(voucher.id)}
                            
                          >
                            ✕ Видалити
                          </button>
                        </td>
                      </tr>
                    );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {activeTab === 'stats' && (
        <div className="tab-content">
          <div className="card">
            <h2>📊 Статистика учнів</h2>
            {message && (
              <div className={`alert alert-${message.type}`}>
                {message.text}
              </div>
            )}
            <div className="filters-row">
              <div className="filters-item">
                <label style={{ display: 'block', marginBottom: '5px', fontSize: '12px', fontWeight: 'bold', color: '#666' }}>
                  🔍 Пошук за іменем:
                </label>
                <input
                  type="text"
                  placeholder="Введіть ім'я учня..."
                  value={searchName}
                  onChange={(e) => setSearchName(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    border: '1px solid #ddd',
                    borderRadius: '4px',
                    fontSize: '14px',
                    boxSizing: 'border-box'
                  }}
                />
              </div>
              <div className="filters-item">
                <label style={{ display: 'block', marginBottom: '5px', fontSize: '12px', fontWeight: 'bold', color: '#666' }}>
                  📚 Фільтр за класом:
                </label>
                <select
                  value={selectedClassFilter}
                  onChange={(e) => setSelectedClassFilter(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    border: '1px solid #ddd',
                    borderRadius: '4px',
                    fontSize: '14px',
                    boxSizing: 'border-box'
                  }}
                >
                  <option value="">Усі класи</option>
                  <option value="(Без класу)">(Без класу)</option>
                  {Array.from(new Set((stats || []).map(s => s.class_name)))
                    .filter(c => c && c !== '(Без класу)')
                    .sort()
                    .map(className => (
                      <option key={className} value={className}>{className}</option>
                    ))}
                </select>
              </div>
              <button className="btn-secondary" onClick={() => fetchStats()}>
                🔄 Оновити
              </button>
            </div>
            {loading ? (
              <div className="loading">Завантаження...</div>
            ) : !stats || stats.length === 0 ? (
              <div className="alert alert-info">Статистика не доступна</div>
            ) : (
              <div className="stats-table">
                {(() => {
                  const filtered = (stats || []).filter(stat => {
                    const matchName = stat.name.toLowerCase().includes(searchName.toLowerCase());
                    const matchClass = !selectedClassFilter || stat.class_name === selectedClassFilter;
                    return matchName && matchClass;
                  });
                  
                  return (
                    <>
                      <div style={{ marginBottom: '10px', fontSize: '13px', color: '#666' }}>
                        📈 Показано: {filtered.length} з {stats.length} учнів
                      </div>
                      <table>
                        <thead>
                          <tr>
                            <th>Учень</th>
                            <th>📚 Клас</th>
                            <th>📋 Всього</th>
                            <th>✓ Використано</th>
                            <th>⚠️ Залишилось</th>
                          </tr>
                        </thead>
                        <tbody>
                          {filtered.length === 0 ? (
                            <tr>
                              <td colSpan="5" style={{ padding: '20px', textAlign: 'center', color: '#999' }}>
                                Немає результатів за цими фільтрами
                              </td>
                            </tr>
                          ) : (
                            filtered.map(stat => (
                              <tr key={stat.id} style={{ backgroundColor: stat.remaining === 0 ? '#fffbea' : 'transparent' }}>
                                <td style={{ fontWeight: stat.remaining === 0 ? 'bold' : 'normal' }}>
                                  {stat.name}
                                </td>
                                <td style={{ fontSize: '13px', color: '#666' }}>
                                  {stat.class_name}
                                </td>
                                <td style={{ textAlign: 'center', fontWeight: 'bold' }}>
                                  {stat.total_vouchers}
                                </td>
                                <td>
                                  <span style={{
                                    padding: '4px 8px',
                                    borderRadius: '3px',
                                    backgroundColor: stat.total_uses > 0 ? '#ffebee' : '#f5f5f5',
                                    color: stat.total_uses > 0 ? '#c62828' : '#999',
                                    fontWeight: 'bold',
                                    fontSize: '13px'
                                  }}>
                                    {stat.total_uses}
                                  </span>
                                </td>
                                <td>
                                  <span style={{
                                    padding: '4px 8px',
                                    borderRadius: '3px',
                                    backgroundColor: stat.remaining > 0 ? '#e8f5e9' : '#fff9c4',
                                    color: stat.remaining > 0 ? '#2e7d32' : '#f57f17',
                                    fontWeight: 'bold',
                                    fontSize: '13px'
                                  }}>
                                    {stat.remaining}
                                  </span>
                                </td>
                              </tr>
                            ))
                          )}
                        </tbody>
                      </table>
                    </>
                  );
                })()}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Модальне вікно для підтвердження видалення */}
      {confirmDelete && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.5)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000
        }}>
          <div style={{
            backgroundColor: '#fff',
            padding: '30px',
            borderRadius: '8px',
            boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)',
            maxWidth: '400px',
            width: '90%',
            textAlign: 'center'
          }}>
            <h3 style={{ marginTop: 0, color: '#d32f2f' }}>⚠️ Підтвердження видалення</h3>
            <p style={{ color: '#666', marginBottom: '20px' }}>
              Ви впевнені, що хочете видалити цей талон? Цю дію неможна скасувати.
            </p>
            <div className="modal-actions-row">
              <button
                className="btn-secondary modal-action-btn"
                onClick={() => setConfirmDelete(null)}
              >
                ❌ Скасувати
              </button>
              <button
                className="btn-danger modal-action-btn"
                onClick={confirmDeleteVoucher}
              >
                ✓ Видалити
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Student Profile Modal */}
      {selectedStudentProfile && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.6)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 2000,
          padding: '20px'
        }}>
          <div
            className="student-profile-modal-content"
            style={{
              backgroundColor: '#fff',
              borderRadius: '8px',
              boxShadow: '0 4px 12px rgba(0, 0, 0, 0.2)'
            }}
          >
            <div className="student-profile-modal-header">
              <h2 style={{ margin: 0, color: '#333' }}>👤 Профіль учня</h2>
              <button
                className="modal-close-btn"
                onClick={() => setSelectedStudentProfile(null)}
              >
                ✕
              </button>
            </div>

            {/* Student Info Card */}
            <div style={{
              backgroundColor: '#f5f5f5',
              padding: '20px',
              borderRadius: '8px',
              marginBottom: '20px'
            }}>
              <table className="student-profile-info-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
                <tbody>
                  <tr>
                    <td style={{ padding: '10px', fontWeight: 'bold', textAlign: 'left' }}>Ім'я:</td>
                    <td style={{ padding: '10px' }}>{selectedStudentProfile.name}</td>
                  </tr>
                  <tr>
                    <td style={{ padding: '10px', fontWeight: 'bold', textAlign: 'left' }}>Username:</td>
                    <td style={{ padding: '10px' }}>{selectedStudentProfile.username}</td>
                  </tr>
                  <tr>
                    <td style={{ padding: '10px', fontWeight: 'bold', textAlign: 'left' }}>Клас:</td>
                    <td style={{ padding: '10px' }}>
                      {selectedStudentProfile.class_id 
                        ? classesList?.find(c => c.id === selectedStudentProfile.class_id)?.name || 'N/A'
                        : '(Без класу)'}
                    </td>
                  </tr>
                  <tr>
                    <td style={{ padding: '10px', fontWeight: 'bold', textAlign: 'left' }}>Присутність:</td>
                    <td style={{ padding: '10px' }}>
                      {selectedStudentProfile.present ? '✓ Присутній' : '✗ Відсутній'}
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>

            {/* Vouchers Section */}
            <h3 style={{ marginTop: '30px', marginBottom: '15px', color: '#333' }}>🎫 Талони учня ({studentVouchers.length})</h3>
            
            {loading ? (
              <div style={{ padding: '20px', textAlign: 'center', color: '#666' }}>Завантаження талонів...</div>
            ) : studentVouchers.length === 0 ? (
              <div style={{ padding: '20px', textAlign: 'center', color: '#999', backgroundColor: '#f9f9f9', borderRadius: '4px' }}>
                Талонів не знайдено
              </div>
            ) : (
              <div className="student-vouchers-grid">
                {studentVouchers.map(voucher => (
                  <div key={voucher.id} style={{
                    border: '1px solid #ddd',
                    borderRadius: '8px',
                    padding: '15px',
                    backgroundColor: '#fafafa',
                    boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
                  }}>
                    {/* Voucher Code */}
                    <div style={{ marginBottom: '10px', padding: '10px', backgroundColor: '#f0f0f0', borderRadius: '4px', wordBreak: 'break-all', fontFamily: 'monospace', fontSize: '12px' }}>
                      <strong>Код:</strong> {voucher.qr_code}
                    </div>

                    {/* Voucher Info */}
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px', marginBottom: '10px' }}>
                      <tbody>
                        <tr>
                          <td style={{ padding: '5px 0', fontWeight: 'bold' }}>Статус:</td>
                          <td style={{ padding: '5px 0', textAlign: 'right' }}>
                            <span style={{
                              padding: '2px 6px',
                              borderRadius: '3px',
                              backgroundColor: voucher.status === 'active' ? '#c8e6c9' : '#fff9c4',
                              color: voucher.status === 'active' ? '#2e7d32' : '#f57f17',
                              fontSize: '11px'
                            }}>
                              {voucher.status === 'active' ? '✓ Активний' : 'Неактивний'}
                            </span>
                          </td>
                        </tr>
                        <tr>
                          <td style={{ padding: '5px 0', fontWeight: 'bold' }}>Використань:</td>
                          <td style={{ padding: '5px 0', textAlign: 'right' }}>{voucher.current_uses}/{voucher.max_uses}</td>
                        </tr>
                        <tr>
                          <td style={{ padding: '5px 0', fontWeight: 'bold' }}>Створено:</td>
                          <td style={{ padding: '5px 0', textAlign: 'right', fontSize: '12px' }}>{voucher.created_date}</td>
                        </tr>
                        {voucher.expires_date && (
                          <tr>
                            <td style={{ padding: '5px 0', fontWeight: 'bold' }}>До:</td>
                            <td style={{ padding: '5px 0', textAlign: 'right', fontSize: '12px', color: '#d32f2f' }}>
                              {voucher.expires_date}
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>

                    {/* QR Code Preview (if available) */}
                    {voucher.qrImage && (
                      <div style={{ marginBottom: '10px', textAlign: 'center' }}>
                        <img 
                          src={voucher.qrImage} 
                          alt="QR Code" 
                          style={{ maxWidth: '150px', border: '1px solid #ddd', padding: '5px', backgroundColor: '#fff' }}
                        />
                      </div>
                    )}

                    {/* Delete Button */}
                    <button
                      className="btn-danger btn-small voucher-delete-btn"
                      onClick={() => deleteStudentVoucher(voucher.id)}
                    >
                      ✕ Видалити талон
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {activeTab === 'settings' && (
        <AdminSettings />
      )}
    </div>
  );
}

export default AdminDashboard;


