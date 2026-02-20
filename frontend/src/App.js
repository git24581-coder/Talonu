import React, { useState, useEffect } from 'react';
import { HashRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Navbar from './components/Navbar.js';
import Login from './pages/Login.js';
import Register from './pages/Register.js';
import StudentDashboard from './pages/StudentDashboard.js';
import CashierDashboard from './pages/CashierDashboard.js';
import AdminDashboard from './pages/AdminDashboard.js';
import AdminClasses from './pages/AdminClasses.js';
import TeacherDashboard from './pages/TeacherDashboard.js';
import apiClient from './api/client.js';
import './App.css';

function App() {
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // Initialize from localStorage
  useEffect(() => {
    const storedToken = localStorage.getItem('token');
    const storedUser = localStorage.getItem('user');
    
    console.log('🔧 App.js initialization:');
    console.log('  Token from localStorage:', storedToken ? storedToken.substring(0, 30) + '...' : 'NOT FOUND');
    console.log('  User from localStorage:', storedUser ? 'EXISTS' : 'NOT FOUND');
    
    if (storedToken) {
      setToken(storedToken);
      console.log('✓ Token will be injected by apiClient interceptor');
    }
    
    if (storedUser) {
      try {
        setUser(JSON.parse(storedUser));
        console.log('✓ User parsed from localStorage');
      } catch (e) {
        console.error('❌ Failed to parse stored user:', e);
      }
    }
    
    setLoading(false);
  }, []);

  const handleLogin = (newToken, newUser) => {
    setToken(newToken);
    setUser(newUser);
    localStorage.setItem('token', newToken);
    localStorage.setItem('user', JSON.stringify(newUser));
    console.log('✓ User logged in, token stored in localStorage');
  };

  const handleLogout = () => {
    setToken(null);
    setUser(null);
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    try {
      apiClient.post('/api/auth/logout').catch(() => {});
    } catch (e) {
      // ignore
    }
  };

  if (loading) {
    return <div style={{ padding: '20px', textAlign: 'center' }}>Завантаження...</div>;
  }
  if (!token) {
    return (
      <Router>
        <Routes>
          <Route path="/login" element={<Login onLogin={handleLogin} />} />
          <Route path="/register" element={<Register onLogin={handleLogin} />} />
          <Route path="*" element={<Navigate to="/login" />} />
        </Routes>
      </Router>
    );
  }

  return (
    <Router>
      <Navbar user={user} onLogout={handleLogout} />
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" />} />
        <Route path="/classes" element={<AdminClasses />} />
        <Route path="/my-class" element={<TeacherDashboard />} />
        <Route
          path="/dashboard"
          element={
            user?.role === 'student' ? (
              <StudentDashboard />
            ) : user?.role === 'cashier' ? (
              <CashierDashboard />
            ) : user?.role === 'admin' ? (
              <AdminDashboard />
            ) : user?.role === 'teacher' ? (
              <TeacherDashboard />
            ) : (
              <Navigate to="/login" />
            )
          }
        />
        <Route path="*" element={<Navigate to="/dashboard" />} />
      </Routes>
    </Router>
  );
}

export default App;
