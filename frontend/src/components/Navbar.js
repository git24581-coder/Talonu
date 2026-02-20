import React from 'react';
import { useNavigate } from 'react-router-dom';
import apiClient from '../api/client.js';

function Navbar({ user, onLogout }) {
  const navigate = useNavigate();

  const handleLogout = async () => {
    try {
      await apiClient.post('/api/auth/logout');
    } catch (error) {
      console.error('Logout error:', error);
    }
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    onLogout();
    navigate('/login');
  };

  return (
    <nav className="navbar">
      <div className="navbar-brand">🎓 Шкільні талони</div>
      <div className="navbar-right">
        <div className="navbar-actions">
          <div className="navbar-user">
            <span>{user?.username || user?.name || 'User'}</span>
            <span>({user?.role || 'guest'})</span>
          </div>
          <button className="btn-danger btn-small navbar-logout-btn" title="Натисніть для виходу з системи" onClick={handleLogout}>
            Вихід
          </button>
        </div>
      </div>
    </nav>
  );
}

export default Navbar;
