import React, { useState, useEffect } from 'react';
import apiClient from '../api/client.js';
import { useNavigate } from 'react-router-dom';
import './Auth.css';

const TEXT = {
  brandAria: '\u0423\u043f\u0440\u0430\u0432\u043b\u0456\u043d\u043d\u044f \u0448\u043a\u0456\u043b\u044c\u043d\u0438\u043c\u0438 \u0442\u0430\u043b\u043e\u043d\u0430\u043c\u0438',
  brandTop: '\u0423\u043f\u0440\u0430\u0432\u043b\u0456\u043d\u043d\u044f',
  brandBottom: '\u0448\u043a\u0456\u043b\u044c\u043d\u0438\u043c\u0438 \u0442\u0430\u043b\u043e\u043d\u0430\u043c\u0438',
  title: '\u0420\u0435\u0454\u0441\u0442\u0440\u0430\u0446\u0456\u044f',
  errorLabel: '\u041f\u043e\u043c\u0438\u043b\u043a\u0430',
  errorFallback: '\u041f\u043e\u043c\u0438\u043b\u043a\u0430 \u0440\u0435\u0454\u0441\u0442\u0440\u0430\u0446\u0456\u0457',
  fullName: '\u041f\u043e\u0432\u043d\u0435 \u0456\u043c\'\u044f',
  username: '\u0406\u043c\'\u044f \u043a\u043e\u0440\u0438\u0441\u0442\u0443\u0432\u0430\u0447\u0430',
  password: '\u041f\u0430\u0440\u043e\u043b\u044c',
  role: '\u0420\u043e\u043b\u044c',
  class: '\u041a\u043b\u0430\u0441',
  student: '\u0423\u0447\u0435\u043d\u044c',
  cashier: '\u041a\u0430\u0441\u0438\u0440',
  teacher: '\u0412\u0447\u0438\u0442\u0435\u043b\u044c',
  noClass: '(\u0411\u0435\u0437 \u043a\u043b\u0430\u0441\u0443)',
  loading: '\u0420\u0435\u0454\u0441\u0442\u0440\u0430\u0446\u0456\u044f...',
  submit: '\u0417\u0430\u0440\u0435\u0454\u0441\u0442\u0440\u0443\u0432\u0430\u0442\u0438\u0441\u044f',
  accountPrompt: '\u0412\u0436\u0435 \u043c\u0430\u0454\u0442\u0435 \u0430\u043a\u0430\u0443\u043d\u0442?',
  login: '\u0423\u0432\u0456\u0439\u0442\u0438'
};

const ICONS = {
  cap: '\uD83C\uDF93',
  card: '\uD83D\uDCB3',
  teacher: '\uD83D\uDC68\u200D\uD83C\uDFEB'
};

function Register({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [role, setRole] = useState('student');
  const [classId, setClassId] = useState('');
  const [classes, setClasses] = useState([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await apiClient.post('/api/auth/register', {
        username,
        password,
        name,
        role,
        class_id: classId || undefined
      });

      const loginResponse = await apiClient.post('/api/auth/login', {
        username,
        password
      });

      onLogin(loginResponse.data.token, loginResponse.data.user);
      navigate('/dashboard');
    } catch (err) {
      setError(err.response?.data?.error || TEXT.errorFallback);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    let cancelled = false;

    (async () => {
      try {
        const resp = await apiClient.get('/api/classes/public');
        if (!cancelled) {
          setClasses(resp.data || []);
        }
      } catch (e) {
        // Ignore loading errors for optional classes list.
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="auth-container register-page">
      <div className="auth-card register-card">
        <div className="login-brand" aria-label={TEXT.brandAria}>
          <p className="login-brand-line">
            <span className="login-brand-icon" aria-hidden="true">{ICONS.cap}</span>
            {TEXT.brandTop}
          </p>
          <p className="login-brand-line">{TEXT.brandBottom}</p>
        </div>

        <h2 className="register-title">{TEXT.title}</h2>

        {error && (
          <div className="alert alert-error">
            <strong>{TEXT.errorLabel}:</strong> {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="register-form">
          <label className="sr-only" htmlFor="register-name">{TEXT.fullName}</label>
          <input
            id="register-name"
            name="name"
            type="text"
            placeholder={TEXT.fullName}
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
          />

          <label className="sr-only" htmlFor="register-username">{TEXT.username}</label>
          <input
            id="register-username"
            name="username"
            type="text"
            placeholder={TEXT.username}
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
          />

          <label className="sr-only" htmlFor="register-password">{TEXT.password}</label>
          <input
            id="register-password"
            name="password"
            type="password"
            placeholder={TEXT.password}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />

          <label className="sr-only" htmlFor="register-role">{TEXT.role}</label>
          <select
            id="register-role"
            name="role"
            value={role}
            onChange={(e) => setRole(e.target.value)}
          >
            <option value="student">{`${ICONS.cap} ${TEXT.student}`}</option>
            <option value="cashier">{`${ICONS.card} ${TEXT.cashier}`}</option>
            <option value="teacher">{`${ICONS.teacher} ${TEXT.teacher}`}</option>
          </select>

          {role === 'student' && (
            <>
              <label className="sr-only" htmlFor="register-class">{TEXT.class}</label>
              <select
                id="register-class"
                name="class_id"
                value={classId}
                onChange={(e) => setClassId(e.target.value)}
              >
                <option value="">{TEXT.noClass}</option>
                {classes.map((cls) => (
                  <option key={cls.id} value={cls.id}>
                    {cls.name}
                  </option>
                ))}
              </select>
            </>
          )}

          <button
            type="submit"
            disabled={loading}
            className="btn-primary register-submit"
          >
            {loading ? TEXT.loading : TEXT.submit}
          </button>
        </form>

        <p className="auth-link register-link">
          {TEXT.accountPrompt} <a href="/login">{TEXT.login}</a>
        </p>
      </div>
    </div>
  );
}

export default Register;