import React, { useState } from 'react';
import apiClient from '../api/client.js';
import { useNavigate } from 'react-router-dom';
import './Auth.css';

function Login({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await apiClient.post('/api/auth/login', {
        username,
        password
      });

      onLogin(response.data.token, response.data.user);
      navigate('/dashboard');
    } catch (err) {
      const errorMsg = err.response?.data?.error || err.message || 'Помилка входу';
      setError(errorMsg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container login-page">
      <div className="auth-card login-card">
        <div className="login-brand" aria-label="Управління шкільними талонами">
          <p className="login-brand-line">
            <span className="login-brand-icon" aria-hidden="true">🎓</span>
            Управління
          </p>
          <p className="login-brand-line">шкільними талонами</p>
        </div>

        <h2 className="login-title">Вхід в систему</h2>

        {error && (
          <div className="alert alert-error">
            <strong>Помилка:</strong> {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="login-form">
          <label className="sr-only" htmlFor="login-username">Ім'я користувача</label>
          <input
            id="login-username"
            name="username"
            type="text"
            placeholder="Ім'я користувача"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            autoFocus
          />

          <label className="sr-only" htmlFor="login-password">Пароль</label>
          <input
            id="login-password"
            name="password"
            type="password"
            placeholder="Пароль"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />

          <button
            type="submit"
            disabled={loading}
            className="btn-primary login-submit"
          >
            🔒 {loading ? 'Вхід...' : 'Увійти'}
          </button>
        </form>

        <p className="auth-link login-link">
          Немаєте акаунту? <a href="/register">Зареєструватися тут</a>
        </p>
      </div>
    </div>
  );
}

export default Login;
