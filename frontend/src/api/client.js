import axios from 'axios';

function resolveApiBaseUrl() {
  if (process.env.REACT_APP_API_URL) {
    return process.env.REACT_APP_API_URL;
  }

  // For mobile devices on the same LAN, use the current host instead of localhost.
  if (typeof window !== 'undefined' && window.location?.hostname) {
    const protocol = window.location.protocol || 'http:';
    const host = window.location.hostname;
    return `${protocol}//${host}:3000`;
  }

  return 'http://localhost:3000';
}

const instance = axios.create({
  baseURL: resolveApiBaseUrl(),
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor - add token if available
instance.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor - handle 401 errors
instance.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export default instance;
