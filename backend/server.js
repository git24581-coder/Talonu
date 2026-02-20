require('dotenv').config();
const express = require('express');
const { db, initDb } = require('./db-wrapper');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const QRCode = require('qrcode');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const compression = require('compression');
const { body, validationResult } = require('express-validator');
const crypto = require('crypto');
const adminConfig = require('./admin-config');
const IORedis = require('ioredis');
const { Queue, QueueScheduler } = require('bullmq');
const clientProm = require('prom-client');
const dbCache = require('./db-cache');
const { monitorEventLoopDelay } = require('perf_hooks');

const app = express();
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const IS_PRODUCTION = NODE_ENV === 'production';
const JWT_SECRET = process.env.JWT_SECRET || 'please-change-this-secret-in-production';
const DEFAULT_JWT_SECRET = 'please-change-this-secret-in-production';
const REFRESH_COOKIE_NAME = 'refreshToken';
const REFRESH_COOKIE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

app.disable('x-powered-by');

const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || '12', 10);
// Voucher expiration hours (configurable via env)
const VOUCHER_EXPIRY_HOURS = parseInt(process.env.VOUCHER_EXPIRY_HOURS || '9', 10);
// Demo seed is disabled by default; set AUTO_SEED_DEMO_DATA=true to enable.
const AUTO_SEED_DEMO_DATA = String(process.env.AUTO_SEED_DEMO_DATA || 'false').toLowerCase() === 'true';
const MAX_INPUT_STRING_LENGTH = getEnvInt('MAX_INPUT_STRING_LENGTH', 4096, 256, 65536);
const PROTOTYPE_POLLUTION_KEYS = new Set(['__proto__', 'prototype', 'constructor']);
const VALID_USER_ROLES = new Set(['student', 'teacher', 'cashier', 'admin']);
const SELF_REGISTER_ALLOWED_ROLES = new Set(
  String(process.env.SELF_REGISTER_ALLOWED_ROLES || 'student')
    .split(',')
    .map((roleName) => String(roleName || '').trim().toLowerCase())
    .filter((roleName) => VALID_USER_ROLES.has(roleName))
);
if (SELF_REGISTER_ALLOWED_ROLES.size === 0) {
  SELF_REGISTER_ALLOWED_ROLES.add('student');
}

function getEnvInt(name, fallback, min = 1, max = Number.MAX_SAFE_INTEGER) {
  const parsed = Number.parseInt(process.env[name] || '', 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(min, Math.min(max, parsed));
}

function getEnvFloat(name, fallback, min = 0, max = 1) {
  const parsed = Number.parseFloat(process.env[name] || '');
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(min, Math.min(max, parsed));
}

function normalizeRole(roleValue) {
  const normalized = String(roleValue || 'student').trim().toLowerCase();
  return VALID_USER_ROLES.has(normalized) ? normalized : 'student';
}

function isStrongPassword(password) {
  if (typeof password !== 'string') return false;
  if (password.length < 10 || password.length > 128) return false;
  if (!/[a-z]/.test(password)) return false;
  if (!/[A-Z]/.test(password)) return false;
  if (!/\d/.test(password)) return false;
  if (!/[^A-Za-z0-9]/.test(password)) return false;
  return true;
}

function normalizeSameSite(rawValue) {
  const normalized = String(rawValue || '').trim().toLowerCase();
  if (normalized === 'strict') return 'Strict';
  if (normalized === 'lax') return 'Lax';
  if (normalized === 'none') return 'None';
  return IS_PRODUCTION ? 'Strict' : 'Lax';
}

const REFRESH_COOKIE_SAMESITE = normalizeSameSite(
  process.env.REFRESH_COOKIE_SAMESITE || (IS_PRODUCTION ? 'Strict' : 'Lax')
);

function getRefreshCookieOptions() {
  const cookieOptions = {
    httpOnly: true,
    secure: IS_PRODUCTION,
    sameSite: REFRESH_COOKIE_SAMESITE,
    maxAge: REFRESH_COOKIE_MAX_AGE_MS,
    path: '/api/auth'
  };

  const cookieDomain = String(process.env.REFRESH_COOKIE_DOMAIN || '').trim();
  if (cookieDomain) {
    cookieOptions.domain = cookieDomain;
  }

  if (cookieOptions.sameSite === 'None') {
    cookieOptions.secure = true;
  }

  return cookieOptions;
}

function getRefreshCookieClearOptions() {
  const cookieOptions = getRefreshCookieOptions();
  delete cookieOptions.maxAge;
  return cookieOptions;
}

function ensureSecurityConfiguration() {
  if (!IS_PRODUCTION) return;

  if (!JWT_SECRET || JWT_SECRET === DEFAULT_JWT_SECRET || JWT_SECRET.length < 32) {
    throw new Error('Unsafe JWT_SECRET in production. Set a random value with length >= 32.');
  }

  const rawOrigins = String(process.env.CORS_ORIGINS || '').trim();
  if (!rawOrigins) {
    throw new Error('CORS_ORIGINS must be set in production.');
  }

  const parsedOrigins = rawOrigins.split(',').map((origin) => origin.trim()).filter(Boolean);
  if (parsedOrigins.length === 0 || parsedOrigins.includes('*')) {
    throw new Error('CORS_ORIGINS must contain explicit origins only (wildcard is not allowed).');
  }

  if (SELF_REGISTER_ALLOWED_ROLES.has('admin')) {
    throw new Error('SELF_REGISTER_ALLOWED_ROLES must not include admin in production.');
  }
}

function safeTrimmedString(value, maxLen = MAX_INPUT_STRING_LENGTH) {
  if (typeof value !== 'string') return value;
  const withoutNulls = value.replace(/\u0000/g, '');
  if (withoutNulls.length <= maxLen) return withoutNulls;
  return withoutNulls.slice(0, maxLen);
}

function sanitizeInputValue(value, depth = 0) {
  if (depth > 20) {
    return null;
  }

  if (typeof value === 'string') {
    return safeTrimmedString(value);
  }

  if (Array.isArray(value)) {
    return value.map((entry) => sanitizeInputValue(entry, depth + 1));
  }

  if (value && typeof value === 'object') {
    const sanitized = {};
    for (const [key, entry] of Object.entries(value)) {
      if (PROTOTYPE_POLLUTION_KEYS.has(key)) continue;
      sanitized[key] = sanitizeInputValue(entry, depth + 1);
    }
    return sanitized;
  }

  return value;
}

function tryDecodeBearerUser(req) {
  try {
    const authHeader = req.headers.authorization || '';
    if (!authHeader.startsWith('Bearer ')) return null;
    const token = authHeader.slice('Bearer '.length).trim();
    if (!token) return null;
    return jwt.verify(token, JWT_SECRET);
  } catch (err) {
    return null;
  }
}

const loginValidationRules = [
  body('username')
    .exists({ checkFalsy: true })
    .withMessage('Username is required')
    .isString()
    .withMessage('Username must be a string')
    .trim()
    .isLength({ min: 3, max: 64 })
    .withMessage('Username length must be 3-64 characters'),
  body('password')
    .exists({ checkFalsy: true })
    .withMessage('Password is required')
    .isString()
    .withMessage('Password must be a string')
    .isLength({ min: 1, max: 128 })
    .withMessage('Password length is invalid')
];

const registerValidationRules = [
  body('username')
    .exists({ checkFalsy: true })
    .withMessage('Username is required')
    .isString()
    .withMessage('Username must be a string')
    .trim()
    .isLength({ min: 3, max: 64 })
    .withMessage('Username length must be 3-64 characters')
    .matches(/^[a-zA-Z0-9_.@-]+$/)
    .withMessage('Username contains forbidden characters'),
  body('password')
    .exists({ checkFalsy: true })
    .withMessage('Password is required')
    .isString()
    .withMessage('Password must be a string')
    .isLength({ min: 10, max: 128 })
    .withMessage('Password length must be 10-128 characters'),
  body('name')
    .optional({ nullable: true })
    .isString()
    .withMessage('Name must be a string')
    .trim()
    .isLength({ min: 2, max: 120 })
    .withMessage('Name length must be 2-120 characters'),
  body('role')
    .optional({ nullable: true })
    .isString()
    .withMessage('Role must be a string')
    .trim()
    .custom((value) => VALID_USER_ROLES.has(String(value || '').toLowerCase()))
    .withMessage('Role is invalid'),
  body('class_id')
    .optional({ nullable: true })
    .isString()
    .withMessage('class_id must be a string')
    .trim()
    .isLength({ min: 1, max: 64 })
    .withMessage('class_id length is invalid')
];

function handleValidationErrors(req, res) {
  const errors = validationResult(req);
  if (errors.isEmpty()) return false;

  const details = errors.array({ onlyFirstError: true }).map((entry) => ({
    field: entry.path,
    message: entry.msg
  }));

  res.status(400).json({ error: 'Invalid input data', details });
  return true;
}

function respondAuthFailure(res, message = 'Невірне ім\'я користувача або пароль') {
  setTimeout(() => {
    if (!res.headersSent) {
      res.status(401).json({ error: message });
    }
  }, LOGIN_FAILURE_DELAY_MS);
}

function isAllowedRequestOrigin(origin, req) {
  if (!origin || typeof origin !== 'string') return false;

  if (allowedOrigins && allowedOrigins.includes(origin)) {
    return true;
  }

  const host = req.get('host');
  const forwardedProto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
  const proto = forwardedProto || req.protocol || 'http';
  if (host && origin === `${proto}://${host}`) {
    return true;
  }

  if (!IS_PRODUCTION && isLocalIP(origin)) {
    return true;
  }

  return false;
}

const JSON_BODY_LIMIT = process.env.JSON_BODY_LIMIT || '64kb';
const URLENCODED_BODY_LIMIT = process.env.URLENCODED_BODY_LIMIT || '64kb';
const REQUEST_URL_MAX_LENGTH = getEnvInt('REQUEST_URL_MAX_LENGTH', 2048, 512, 16384);
const MAX_CONCURRENT_REQUESTS = getEnvInt('MAX_CONCURRENT_REQUESTS', 400, 50, 5000);
const API_RATE_LIMIT_WINDOW_MS = getEnvInt('API_RATE_LIMIT_WINDOW_MS', 60 * 1000, 1000, 60 * 60 * 1000);
const API_RATE_LIMIT_MAX = getEnvInt('API_RATE_LIMIT_MAX', 300, 10, 20000);
const AUTH_RATE_LIMIT_WINDOW_MS = getEnvInt('AUTH_RATE_LIMIT_WINDOW_MS', 15 * 60 * 1000, 1000, 60 * 60 * 1000);
const AUTH_RATE_LIMIT_MAX = getEnvInt('AUTH_RATE_LIMIT_MAX', 20, 3, 500);
const LOGIN_FAILURE_DELAY_MS = getEnvInt('LOGIN_FAILURE_DELAY_MS', 350, 100, 5000);
const HEAVY_RATE_LIMIT_WINDOW_MS = getEnvInt('HEAVY_RATE_LIMIT_WINDOW_MS', 60 * 1000, 1000, 60 * 60 * 1000);
const HEAVY_RATE_LIMIT_MAX = getEnvInt('HEAVY_RATE_LIMIT_MAX', 120, 10, 2000);
const ACCESS_LOG_ENABLED = String(process.env.ACCESS_LOG_ENABLED || (process.env.NODE_ENV === 'production' ? 'false' : 'true')).toLowerCase() === 'true';
const ACCESS_LOG_SAMPLE_RATE = getEnvFloat('ACCESS_LOG_SAMPLE_RATE', 1, 0.01, 1);
const MAX_HEAP_USED_MB = getEnvInt('MAX_HEAP_USED_MB', 1024, 128, 16384);
const MAX_EVENT_LOOP_P99_LAG_MS = getEnvInt('MAX_EVENT_LOOP_P99_LAG_MS', 250, 20, 5000);
const QR_MEMORY_CACHE_TTL_MS = getEnvInt('QR_MEMORY_CACHE_TTL_MS', 7 * 24 * 60 * 60 * 1000, 1000, 30 * 24 * 60 * 60 * 1000);
const QR_MEMORY_CACHE_MAX_ITEMS = getEnvInt('QR_MEMORY_CACHE_MAX_ITEMS', 3000, 100, 20000);

const SERVER_KEEP_ALIVE_TIMEOUT_MS = getEnvInt('SERVER_KEEP_ALIVE_TIMEOUT_MS', 65 * 1000, 1000, 180 * 1000);
const SERVER_HEADERS_TIMEOUT_MS = getEnvInt('SERVER_HEADERS_TIMEOUT_MS', 66 * 1000, 2000, 180 * 1000);
const SERVER_REQUEST_TIMEOUT_MS = getEnvInt('SERVER_REQUEST_TIMEOUT_MS', 30 * 1000, 2000, 180 * 1000);
const SERVER_SOCKET_TIMEOUT_MS = getEnvInt('SERVER_SOCKET_TIMEOUT_MS', 35 * 1000, 2000, 180 * 1000);
const SERVER_MAX_CONNECTIONS = getEnvInt('SERVER_MAX_CONNECTIONS', 2000, 100, 50000);
const SHUTDOWN_TIMEOUT_MS = getEnvInt('SHUTDOWN_TIMEOUT_MS', 10 * 1000, 1000, 60 * 1000);

const eventLoopDelayMonitor = monitorEventLoopDelay({ resolution: 20 });
eventLoopDelayMonitor.enable();
const runtimeMetricsBypassPaths = new Set(['/api/health', '/api/ready', '/metrics']);
let activeRequests = 0;

// Trust proxy FIRST before rate limiting (express-rate-limit validation)
// Set trust proxy to 1 hop instead of true for security with rate limiting
app.set('trust proxy', 1);

// CORS - restrict origins in production, allow localhost:3000 in development
const allowedOrigins = process.env.CORS_ORIGINS ? process.env.CORS_ORIGINS.split(',').map(s => s.trim()) : null;
const defaultDevOrigins = [
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  // Allow access from any local IP address for mobile testing
  // This matches http://192.168.*.* :3000 pattern
];

// Function to check if origin is a local IP
const isLocalIP = (origin) => {
  if (!origin) return true;
  try {
    const url = new URL(origin);
    const hostname = url.hostname;
    // Allow localhost, 127.0.0.1, and any 192.168.* addresses
    return (
      hostname === 'localhost' ||
      hostname === '127.0.0.1' ||
      hostname.startsWith('192.168.') ||
      hostname.startsWith('10.') ||
      hostname.startsWith('172.') ||
      hostname === '0.0.0.0'
    );
  } catch (e) {
    return false;
  }
};

ensureSecurityConfiguration();

function getRuntimePressure() {
  const p99Raw = eventLoopDelayMonitor.percentile(99);
  const eventLoopP99LagMs = Number.isFinite(p99Raw) ? Math.round(p99Raw / 1e6) : 0;
  const memory = process.memoryUsage();
  const heapUsedMb = Math.round(memory.heapUsed / (1024 * 1024));
  const rssMb = Math.round(memory.rss / (1024 * 1024));
  return { eventLoopP99LagMs, heapUsedMb, rssMb, activeRequests };
}

function getOverloadReason() {
  const pressure = getRuntimePressure();
  if (pressure.activeRequests >= MAX_CONCURRENT_REQUESTS) {
    return `too many concurrent requests (${pressure.activeRequests}/${MAX_CONCURRENT_REQUESTS})`;
  }
  if (pressure.heapUsedMb >= MAX_HEAP_USED_MB) {
    return `high heap usage (${pressure.heapUsedMb}MB/${MAX_HEAP_USED_MB}MB)`;
  }
  if (pressure.eventLoopP99LagMs >= MAX_EVENT_LOOP_P99_LAG_MS) {
    return `high event loop lag (${pressure.eventLoopP99LagMs}ms/${MAX_EVENT_LOOP_P99_LAG_MS}ms)`;
  }
  return null;
}

function normalizeRouteForMetrics(req) {
  if (req.route && req.route.path) {
    return `${req.baseUrl || ''}${req.route.path}`;
  }
  const pathValue = req.path || req.originalUrl || 'unknown';
  return String(pathValue)
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/ig, ':uuid')
    .replace(/\/\d+(?=\/|$)/g, '/:id');
}
// ========== DEVELOPMENT CORS HELPER - MUST BE FIRST THING AFTER APP CREATION ==========
// This MUST run before everything else to set CORS headers
if (process.env.NODE_ENV !== 'production') {
  app.use((req, res, next) => {
    const origin = req.get('Origin') || req.get('origin') || 'http://localhost:3000';
    // Always set CORS headers in development for ANY local origin
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS,HEAD,PATCH');
    res.header('Access-Control-Allow-Headers', 'Origin,X-Requested-With,Content-Type,Accept,Authorization');
    res.header('Access-Control-Max-Age', '86400');
    
    // CRITICAL: Handle OPTIONS separately and return immediately
    if (req.method === 'OPTIONS') {
      return res.sendStatus(200);
    }
    next();
  });
  console.log(`✅ Development: CORS headers enabled for ALL origins`);
}

// Standard CORS middleware (required for production cross-origin frontend, e.g. GitHub Pages -> Render)
const corsOptions = {
  origin: (origin, callback) => {
    // Allow non-browser/health-check requests with no Origin header.
    if (!origin) return callback(null, true);

    if (process.env.NODE_ENV !== 'production') {
      return callback(null, true);
    }

    if (allowedOrigins && allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    return callback(null, false);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Origin', 'X-Requested-With', 'Content-Type', 'Accept', 'Authorization'],
  optionsSuccessStatus: 204
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

const mutatingMethods = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
app.use((req, res, next) => {
  if (!IS_PRODUCTION) return next();
  if (!req.path.startsWith('/api')) return next();
  if (!mutatingMethods.has(req.method)) return next();
  if (req.path === '/api/health' || req.path === '/api/ready') return next();

  const origin = req.get('origin') || req.get('Origin') || '';
  if (!isAllowedRequestOrigin(origin, req)) {
    return res.status(403).json({ error: 'Origin is not allowed for this operation' });
  }
  return next();
});

app.use((req, res, next) => {
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(self), geolocation=(), microphone=()');
  res.setHeader('X-Robots-Tag', 'noindex, nofollow');
  next();
});

// Apply Helmet AFTER CORS so CORS headers can be set properly
// Security middleware
const allowUnsafeEval = process.env.ALLOW_UNSAFE_EVAL === 'true';
if (IS_PRODUCTION) {
  const connectSrc = ["'self'"];
  if (allowedOrigins && allowedOrigins.length > 0) {
    connectSrc.push(...allowedOrigins);
  }

  const scriptSrc = allowUnsafeEval
    ? ["'self'", "'unsafe-eval'"]
    : ["'self'"];

  app.use(helmet({
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    referrerPolicy: { policy: 'no-referrer' },
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc,
        connectSrc,
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:'],
        objectSrc: ["'none'"],
        baseUri: ["'none'"],
        frameAncestors: ["'none'"],
        formAction: ["'self'"],
        upgradeInsecureRequests: []
      }
    }
  }));
  console.log(`🔒 Helmet enabled (production mode)`);
} else {
  app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
    hsts: false
  }));
  console.log(`🔒 Helmet enabled with development-safe profile`);
}

app.use((req, res, next) => {
  const requestUrl = req.originalUrl || req.url || '';
  if (requestUrl.length > REQUEST_URL_MAX_LENGTH) {
    return res.status(414).json({ error: 'Request URL is too long' });
  }

  const overloadReason = getOverloadReason();
  if (overloadReason && !runtimeMetricsBypassPaths.has(req.path || '')) {
    return res.status(503).json({
      error: 'Server is temporarily overloaded. Please try again in a few seconds.',
      reason: overloadReason
    });
  }

  activeRequests += 1;
  let released = false;
  const release = () => {
    if (!released) {
      released = true;
      activeRequests = Math.max(0, activeRequests - 1);
    }
  };

  res.on('finish', release);
  res.on('close', release);
  next();
});

app.use((req, res, next) => {
  res.setTimeout(SERVER_REQUEST_TIMEOUT_MS, () => {
    if (!res.headersSent) {
      res.status(503).json({ error: 'Request timeout under load. Please retry.' });
    }
    if (typeof req.destroy === 'function') {
      req.destroy();
    }
  });
  next();
});

app.use(express.json({ limit: JSON_BODY_LIMIT, strict: true }));
app.use(express.urlencoded({ extended: true, limit: URLENCODED_BODY_LIMIT }));
app.use(cookieParser());
// HTTP compression to reduce bandwidth for many concurrent users
app.use(compression({ threshold: 1024 }));

app.use('/api', (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Pragma', 'no-cache');
  next();
});

app.use((req, res, next) => {
  try {
    if (req.body && typeof req.body === 'object') {
      req.body = sanitizeInputValue(req.body);
    }
  } catch (err) {
    return res.status(400).json({ error: 'Invalid request payload' });
  }
  return next();
});

// ========== REDIS + QUEUES + METRICS ==========
// Redis is OPTIONAL - only enable if explicitly configured
const REDIS_URL = process.env.REDIS_URL;
let redis = null;

// Only try to connect to Redis if explicitly configured in environment
if (REDIS_URL) {
  try {
    redis = new IORedis(REDIS_URL, { 
      lazyConnect: true, 
      retryStrategy: () => null, 
      connectTimeout: 2000,
      maxRetriesPerRequest: null,
      enableReadyCheck: false,
      enableOfflineQueue: false,
      showFriendlyErrorStack: false
    });
    
    // Suppress ALL Redis events/errors - not critical
    redis.on('error', () => {});
    redis.on('close', () => {});
    redis.on('reconnecting', () => {});
    redis.on('warning', () => {});
    redis.on('connect', () => {});
    redis.on('ready', () => {});
    
    redis.connect().then(() => {
      console.log('✓ Connected to Redis (optional caching)');
      dbCache.setRedisInstance(redis);
    }).catch(() => {
      redis = null;
    });
  } catch (e) {
    redis = null;
  }
}

// BullMQ queues (will work only if Redis is available)
const qrQueue = redis ? new Queue('qr-generation', { connection: redis }) : null;
const distributeQueue = redis ? new Queue('distribute-vouchers', { connection: redis }) : null;
if (redis) {
  // schedulers help with delayed/retryable jobs
  try { new QueueScheduler('qr-generation', { connection: redis }); } catch (e) {}
  try { new QueueScheduler('distribute-vouchers', { connection: redis }); } catch (e) {}
}

// Prometheus metrics
try {
  clientProm.collectDefaultMetrics({ timeout: 5000 });
} catch (e) {}
const requestCounter = new clientProm.Counter({ name: 'http_requests_total', help: 'Total HTTP requests', labelNames: ['method', 'route', 'status'] });
const voucherCreatedCounter = new clientProm.Counter({ name: 'vouchers_created_total', help: 'Total vouchers created' });
const publicMetricsLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Metrics endpoint rate limit exceeded.'
});

app.get('/metrics', publicMetricsLimiter, async (req, res) => {
  try {
    res.set('Content-Type', clientProm.register.contentType);
    res.end(await clientProm.register.metrics());
  } catch (e) {
    res.status(500).end(e.message);
  }
});

// QR image cache helper: uses Redis when available to avoid regenerating QR codes under load
const qrMemoryCache = new Map();

function getQrMemoryCache(key) {
  const entry = qrMemoryCache.get(key);
  if (!entry) return null;
  if (entry.expiresAt <= Date.now()) {
    qrMemoryCache.delete(key);
    return null;
  }
  // Move to end (simple LRU behavior).
  qrMemoryCache.delete(key);
  qrMemoryCache.set(key, entry);
  return entry.value;
}

function setQrMemoryCache(key, value) {
  qrMemoryCache.set(key, { value, expiresAt: Date.now() + QR_MEMORY_CACHE_TTL_MS });
  while (qrMemoryCache.size > QR_MEMORY_CACHE_MAX_ITEMS) {
    const oldest = qrMemoryCache.keys().next();
    if (oldest.done) break;
    qrMemoryCache.delete(oldest.value);
  }
}

async function getQrImageCached(qrCode) {
  if (!qrCode) return null;
  const key = `qr:${qrCode}`;

  const memoryCached = getQrMemoryCache(key);
  if (memoryCached) return memoryCached;

  if (redis) {
    try {
      const cached = await redis.get(key);
      if (cached) {
        setQrMemoryCache(key, cached);
        return cached;
      }
    } catch (e) {
      // ignore
    }
  }

  try {
    const data = await QRCode.toDataURL(qrCode, { errorCorrectionLevel: 'H', type: 'image/png', width: 500, margin: 2, color: { dark: '#000000', light: '#FFFFFF' } });
    setQrMemoryCache(key, data);
    if (redis) {
      try { await redis.set(key, data, 'EX', 60 * 60 * 24 * 7); } catch (e) {}
    }
    return data;
  } catch (e) {
    return null;
  }
}

// Error handler for JSON parsing errors
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    console.warn(`⚠️  Invalid JSON in request: ${err.message}`);
    return res.status(400).json({ error: 'Invalid JSON in request body' });
  }
  next(err);
});

// Ensure logs directory exists and simple request logging
const logsDir = path.join(__dirname, 'logs');
try { if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir); } catch (e) {}
const logFile = path.join(logsDir, 'app.log');
function appendLog(line) {
  if (!ACCESS_LOG_ENABLED) return;
  const ts = new Date().toISOString();
  fs.appendFile(logFile, `[${ts}] ${line}\n`, () => {});
}

app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    const userId = req.user ? req.user.id : '-';
    const ip = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress || '-';
    if (ACCESS_LOG_ENABLED && Math.random() <= ACCESS_LOG_SAMPLE_RATE) {
      appendLog(`${ip} ${req.method} ${req.originalUrl} ${res.statusCode} ${duration}ms user=${userId}`);
    }
    try {
      requestCounter.inc({
        method: req.method,
        route: normalizeRouteForMetrics(req),
        status: String(res.statusCode)
      });
    } catch (e) {}
  });
  next();
});

// Rate limiters: protect auth endpoints and heavy operations
const apiLimiter = rateLimit({
  windowMs: API_RATE_LIMIT_WINDOW_MS,
  max: API_RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path === '/health' || req.path === '/ready',
  message: 'Too many requests from this IP, please slow down.'
});
const authLimiter = rateLimit({
  windowMs: AUTH_RATE_LIMIT_WINDOW_MS,
  max: AUTH_RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many auth attempts, try again later.'
});
const heavyLimiter = rateLimit({
  windowMs: HEAVY_RATE_LIMIT_WINDOW_MS,
  max: HEAVY_RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many requests to heavy endpoints, slow down.'
});
app.use('/api', apiLimiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);
app.use('/api/auth/refresh', authLimiter);
app.use('/api/vouchers/use', heavyLimiter);
app.use('/api/vouchers/check', heavyLimiter);
app.use('/api/vouchers/my', heavyLimiter);
app.use('/api/vouchers/all', heavyLimiter);
app.use('/api/vouchers/user', heavyLimiter);
app.use('/api/users', heavyLimiter);

// ========== DATABASE INITIALIZATION ==========
// Initialize database (SQLite or PostgreSQL based on DATABASE_URL env var)
console.log('▶️  Initializing database support (SQLite or PostgreSQL)...');

// Database initialization will be called before server starts
const startServer = async () => {
  try {
    // Initialize the database wrapper (creates tables, sets up pool, etc.)
    await initDb();
    console.log('✓ Database initialized successfully');
    
    // Optional demo seed (disabled by default)
    if (AUTO_SEED_DEMO_DATA) {
      console.log('▶️  AUTO_SEED_DEMO_DATA=true, creating demo users/classes...');
      createDefaultUsers();
    } else {
      console.log('⏭️  Demo seed disabled (AUTO_SEED_DEMO_DATA=false). Startup will not create classes/users.');
    }
    
    // Initialize admin config system
    console.log('▶️  Initializing admin config system...');
    adminConfig.initAdminConfig(db, (err) => {
      if (err) {
        console.error('❌ Error initializing admin config:', err);
      } else {
        console.log('✓ Admin config loaded successfully');
      }
    });
    
  } catch (err) {
    console.error('❌ Database initialization failed:', err);
    process.exit(1);
  }
};

// Call database initialization immediately
startServer().catch(err => {
  console.error('❌ Startup error:', err);
  process.exit(1);
});

// Optional HTTPS enforcement
app.use((req, res, next) => {
  if (process.env.ENFORCE_HTTPS === 'true') {
    const proto = req.headers['x-forwarded-proto'] || (req.secure ? 'https' : 'http');
    if (proto !== 'https') {
      return res.redirect('https://' + req.headers.host + req.url);
    }
  }
  next();
});

// Helper: log audit event
function logAudit(userId, action, req, details) {
  try {
    const id = uuidv4();
    const ip = req.ip || req.headers['x-forwarded-for'] || null;
    const ua = req.get('User-Agent') || null;
    db.run('INSERT INTO audit_logs (id, user_id, action, ip, user_agent, details) VALUES (?, ?, ?, ?, ?, ?)',
      [id, userId || null, action, ip, ua, details ? JSON.stringify(details) : null]);
  } catch (e) {
    // ignore logging errors
  }
}

// Helper: create refresh token and store in DB
function createRefreshToken(userId) {
  const token = crypto.randomBytes(64).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const id = uuidv4();
  const expiresAt = new Date(Date.now() + (7 * 24 * 60 * 60 * 1000)).toISOString(); // 7 days
  // store only hash in DB to reduce impact of DB leak
  db.run('INSERT INTO refresh_tokens (id, user_id, token, expires_at) VALUES (?, ?, ?, ?)', [id, userId, tokenHash, expiresAt]);
  return { token, expiresAt };
}

function cleanupExpiredRefreshTokens() {
  const nowIso = new Date().toISOString();
  db.run('DELETE FROM refresh_tokens WHERE expires_at <= ?', [nowIso], (err, result) => {
    if (err) {
      console.error('❌ Refresh token cleanup error:', err);
      return;
    }
    if (result && result.changes > 0) {
      console.log(`🧹 Removed ${result.changes} expired refresh token(s)`);
    }
  });
}

function sanitizeUsername(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_.-@]/g, '')
    .slice(0, 150);
}

// Helper: check if voucher is expired (9 hours from issuance)
function isVoucherExpired(voucher) {
  if (!voucher || !voucher.issued_at) return false;
  
  const issuedTime = new Date(voucher.issued_at);
  const currentTime = new Date();
  const hoursElapsed = (currentTime - issuedTime) / (1000 * 60 * 60);
  
  return hoursElapsed > VOUCHER_EXPIRY_HOURS;
}

// Helper: auto-mark expired vouchers as used
function markExpiredVouchersAsUsed() {
  // Find all active vouchers issued more than 9 hours ago
  db.all(
    `SELECT v.id, v.qr_code, v.student_name FROM vouchers v 
     WHERE v.status = 'active' 
     AND v.issued_at IS NOT NULL
     AND datetime(v.issued_at, '+${VOUCHER_EXPIRY_HOURS} hours') < datetime('now')
     AND v.current_uses < v.max_uses`,
    [],
    (err, expiredVouchers) => {
      if (err) {
        console.error('❌ Error finding expired vouchers:', err);
        return;
      }
      
      if (!expiredVouchers || expiredVouchers.length === 0) return;
      
      console.log(`🕐 Found ${expiredVouchers.length} expired vouchers, marking as used...`);
      
      expiredVouchers.forEach((voucher) => {
        const today = new Date().toISOString().split('T')[0];
        const now = new Date().toTimeString().split(' ')[0];
        const usageId = uuidv4();
        
        // Check if already marked as used today
        db.get(
          'SELECT id FROM voucher_usage WHERE voucher_id = ? AND used_date = ?',
          [voucher.id, today],
          (checkErr, existing) => {
            if (checkErr || existing) return;
            
            // Mark as used by system (no cashier)
            db.run(
              'INSERT INTO voucher_usage (id, voucher_id, used_date, used_time, cashier_id) VALUES (?, ?, ?, ?, ?)',
              [usageId, voucher.id, today, now, null],
              (insertErr) => {
                if (!insertErr) {
                  db.run(
                    'UPDATE vouchers SET current_uses = current_uses + 1 WHERE id = ?',
                    [voucher.id],
                    (updateErr) => {
                      if (!updateErr) {
                        console.log(`  ✓ Voucher ${voucher.qr_code.substring(0, 8)}... marked as expired`);
                      }
                    }
                  );
                }
              }
            );
          }
        );
      });
    }
  );
}

// Функція для створення дефолтних користувачів
function createDefaultUsers() {
  console.log('🔧 createDefaultUsers() почалась');
  
  const defaultUsers = [
    {
      username: 'admin',
      password: 'admin123',
      name: 'Адміністратор',
      role: 'admin'
    },
    {
      username: 'cashier',
      password: 'cashier123',
      name: 'Касир',
      role: 'cashier'
    },
    {
      username: 'teacher',
      password: 'teacher123',
      name: 'Петро Іванович',
      role: 'teacher'
    },
    {
      username: 'student1',
      password: 'student123',
      name: 'Іван Коваленко',
      role: 'student'
    },
    {
      username: 'student2',
      password: 'student123',
      name: 'Марія Петренко',
      role: 'student'
    },
    {
      username: 'student3',
      password: 'student123',
      name: 'Олег Сидоренко',
      role: 'student'
    },
    {
      username: 'student4',
      password: 'student123',
      name: 'Анна Гавриленко',
      role: 'student'
    }
  ];

  // Спочатку створимо клас, якщо його немає
  db.get('SELECT id FROM classes WHERE name = ?', ['9-А'], (err, classRow) => {
    if (!classRow && !err) {
      const classId = uuidv4();
      db.run('INSERT INTO classes (id, name) VALUES (?, ?)', [classId, '9-А'], (cErr) => {
        if (!cErr) {
          console.log('✓ Клас "9-А" створений');
        }
      });
    }
  });

  defaultUsers.forEach((user, idx) => {
    const cleanUsername = String(user.username).trim().toLowerCase();
    console.log(`  [${idx}] Перевіряю користувача: ${cleanUsername}`);
    db.get('SELECT id FROM users WHERE username = ?', [cleanUsername], (err, row) => {
      if (err) {
        console.error(`  ❌ Error checking user ${cleanUsername}:`, err);
        return;
      }
      if (!row) {
        console.log(`    └─ Користувач не існує, створюю...`);
        bcrypt.hash(user.password, BCRYPT_ROUNDS, (hashErr, hashedPassword) => {
          if (hashErr) {
            console.error(`    ❌ Hash error:`, hashErr);
            return;
          }
          const id = uuidv4();
          
          // Для учнів та вчителя - призначимо їх до класу 9-А
          let classId = null;
          if (user.role === 'student' || user.role === 'teacher') {
            db.get('SELECT id FROM classes WHERE name = ?', ['9-А'], (cErr, cRow) => {
              if (cRow) classId = cRow.id;
              insertUser();
            });
          } else {
            insertUser();
          }
          
          function insertUser() {
            db.run(
              'INSERT INTO users (id, username, password, name, role, class_id) VALUES (?, ?, ?, ?, ?, ?)',
              [id, cleanUsername, hashedPassword, user.name, user.role, classId],
              (insertErr) => {
                if (insertErr) {
                  console.error(`    ❌ Insert error:`, insertErr);
                } else {
                  const classInfo = classId ? ` (клас: 9-А)` : '';
                  console.log(`    ✓ Користувач "${cleanUsername}" створений${classInfo} (пароль: "${user.password}")`);
                }
              }
            );
          }
        });
      } else {
        console.log(`    └─ Користувач уже існує`);
      }
    });
  });
}

// Middleware для перевірки JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Токен не знайдений' });
  if (token.length > 4096) return res.status(401).json({ error: 'Невалідний токен' });
  if (!/^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/.test(token)) {
    return res.status(401).json({ error: 'Невалідний токен' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Невалідний токен' });
    req.user = user;
    next();
  });
};

// ============ АУТЕНТИФІКАЦІЯ ============

// Реєстрація
app.post('/api/auth/register', registerValidationRules, async (req, res) => {
  if (handleValidationErrors(req, res)) return;

  const { username, password, name, role } = req.body;
  const { class_id } = req.body || {};

  try {
    // Basic input validation / sanitization
    const cleanUsername = sanitizeUsername(username);
    const cleanName = name ? String(name).trim().replace(/[<>"'`]/g, '') : null;
    const requestedRole = normalizeRole(role);
    const actor = tryDecodeBearerUser(req);
    const createdByAdmin = Boolean(actor && actor.role === 'admin');

    if (!cleanUsername || typeof password !== 'string') {
      return res.status(400).json({ error: 'Invalid registration data.' });
    }

    if (!isStrongPassword(password)) {
      return res.status(400).json({
        error: 'Password must be 10-128 chars and include uppercase, lowercase, digit and special symbol.'
      });
    }

    if (!createdByAdmin && !SELF_REGISTER_ALLOWED_ROLES.has(requestedRole)) {
      return res.status(403).json({ error: 'Self-registration for this role is disabled.' });
    }

    const finalRole = requestedRole;
    const incomingClassId = class_id ? String(class_id).trim() : null;

    if (incomingClassId && !['student', 'teacher'].includes(finalRole)) {
      return res.status(400).json({ error: 'class_id can only be set for student or teacher roles.' });
    }

    // If class_id provided for student/teacher ensure it exists
    if (incomingClassId) {
      const classRow = await new Promise((resolve) => db.get('SELECT id FROM classes WHERE id = ?', [incomingClassId], (e, r) => resolve({ err: e, row: r })));
      if (!classRow || !classRow.row) {
        return res.status(400).json({ error: 'Клас не знайдений' });
      }
    }

    const hashedPassword = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const id = uuidv4();

    db.run(
      'INSERT INTO users (id, username, password, name, role, class_id) VALUES (?, ?, ?, ?, ?, ?)',
      [id, cleanUsername, hashedPassword, cleanName, finalRole, incomingClassId],
      (err) => {
        if (err) {
          return res.status(400).json({ error: 'Користувач уже існує' });
        }
        logAudit(id, 'register', req, { username: cleanUsername, role: finalRole, createdByAdmin });
        res.json({ success: true, message: 'Реєстрація успішна', userId: id });
      }
    );
  } catch (err) {
    res.status(500).json({ error: 'Помилка реєстрації' });
  }
});

// Logout (revoke refresh token)
app.post('/api/auth/logout', authenticateToken, (req, res) => {
  const token = req.cookies && req.cookies[REFRESH_COOKIE_NAME];
  if (token) {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    db.run('DELETE FROM refresh_tokens WHERE token = ?', [tokenHash]);
  }
  res.clearCookie(REFRESH_COOKIE_NAME, getRefreshCookieClearOptions());
  logAudit(req.user?.id, 'logout', req, null);
  res.json({ success: true });
});

// Refresh access token using httpOnly refresh token cookie (with rotation)
app.post('/api/auth/refresh', (req, res) => {
  const token = req.cookies && req.cookies[REFRESH_COOKIE_NAME];
  if (!token) return res.status(401).json({ error: 'Refresh token not found' });
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

  db.get('SELECT * FROM refresh_tokens WHERE token = ?', [tokenHash], (err, row) => {
    if (err || !row) return res.status(401).json({ error: 'Invalid refresh token' });
    if (new Date(row.expires_at) < new Date()) {
      db.run('DELETE FROM refresh_tokens WHERE id = ?', [row.id]);
      return res.status(401).json({ error: 'Refresh token expired' });
    }

    db.get('SELECT * FROM users WHERE id = ?', [row.user_id], (uErr, user) => {
      if (uErr || !user) return res.status(401).json({ error: 'User not found' });
      // rotate: delete old token and create new one
      db.run('DELETE FROM refresh_tokens WHERE id = ?', [row.id], (delErr) => {
        const { token: newRefreshPlain, expiresAt } = createRefreshToken(user.id);
        const cookieOptions = getRefreshCookieOptions();
        res.cookie(REFRESH_COOKIE_NAME, newRefreshPlain, cookieOptions);
        const accessToken = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '15m' });
        logAudit(user.id, 'token_refreshed', req, null);
        res.json({ token: accessToken, expiresAt });
      });
    });
  });
});

// Вхід
app.post('/api/auth/login', loginValidationRules, (req, res) => {
  if (handleValidationErrors(req, res)) return;

  const { username, password } = req.body || {};

  const cleanUsername = sanitizeUsername(username);

  // Simple reliable login: find user and compare password
  db.get('SELECT * FROM users WHERE lower(username) = ? OR username = ?', [cleanUsername, username], async (err, user) => {
    if (err) {
      console.error('Login DB error:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }

    if (!user) {
      logAudit(null, 'login_failed', req, { username: cleanUsername });
      return respondAuthFailure(res);
    }

    // Check account lockout
    try {
      const now = new Date();
      if (user.locked_until && new Date(user.locked_until) > now) {
        logAudit(user.id, 'login_locked', req, null);
        return res.status(423).json({ error: 'Акаунт тимчасово заблоковано. Спробуйте пізніше.' });
      }

      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        // increment failed_attempts and possibly lock
        const maxAttempts = parseInt(process.env.MAX_LOGIN_ATTEMPTS || '5', 10);
        const lockMinutes = parseInt(process.env.LOCK_MINUTES || '15', 10);
        db.run('UPDATE users SET failed_attempts = COALESCE(failed_attempts,0) + 1 WHERE id = ?', [user.id], function(uErr) {
          if (!uErr) {
            db.get('SELECT failed_attempts FROM users WHERE id = ?', [user.id], (qErr, row) => {
              const attempts = row && row.failed_attempts ? row.failed_attempts : 0;
              if (attempts >= maxAttempts) {
                const lockedUntil = new Date(Date.now() + lockMinutes * 60 * 1000).toISOString();
                db.run('UPDATE users SET locked_until = ? WHERE id = ?', [lockedUntil, user.id]);
                logAudit(user.id, 'account_locked', req, { attempts });
              }
            });
          }
        });
        logAudit(user.id, 'login_failed', req, { username: user.username });
        return respondAuthFailure(res);
      }

      // Issue short-lived access token
      const accessToken = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '15m' });
      // create refresh token and set as httpOnly cookie
      const { token: refreshPlain, expiresAt } = createRefreshToken(user.id);
      const cookieOptions = getRefreshCookieOptions();
      console.log(`🍪 Setting refresh cookie. isProduction=${IS_PRODUCTION}, sameSite=${cookieOptions.sameSite}`);
      res.cookie(REFRESH_COOKIE_NAME, refreshPlain, cookieOptions);
      // reset failed attempts on successful login
      db.run('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?', [user.id]);
      logAudit(user.id, 'login_success', req, { username: user.username });
      console.log(`✓ Login successful for user: ${user.username} (role=${user.role})`);
      return res.json({ token: accessToken, user: { id: user.id, username: user.username, role: user.role, name: user.name }, expiresAt });
    } catch (e) {
      console.error('Login processing error:', e);
      return res.status(500).json({ error: 'Помилка входу' });
    }
  });
});

// ============ ТАЛОНИ ============

// Отримати список всіх користувачів (для адміна)
app.get('/api/users', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Доступ заборонений' });
  }

  const kyivTime = new Date(new Date().toLocaleString('en-US', { timeZone: 'Europe/Kyiv' }));
  const today = kyivTime.toISOString().split('T')[0];

  db.all(
    `SELECT u.id, u.username, u.name, u.role, u.class_id,
            CASE WHEN EXISTS (
              SELECT 1
              FROM attendance a
              WHERE a.student_id = u.id
                AND a.attendance_date = ?
                AND a.status = 'present'
            ) THEN 1 ELSE 0 END AS present
     FROM users u
     WHERE u.role IN ('student', 'teacher')
     ORDER BY u.name`,
    [today],
    (err, users) => {
      if (err) return res.status(500).json({ error: 'Помилка отримання користувачів' });

      const normalized = (users || []).map((user) => ({
        ...user,
        present: Boolean(Number(user.present))
      }));

      res.json(normalized);
    }
  );
});

// Отримати талони користувача
app.get('/api/vouchers/my', authenticateToken, (req, res) => {
  db.all(
    'SELECT * FROM vouchers WHERE user_id = ? ORDER BY created_date DESC',
    [req.user.id],
    async (err, vouchers) => {
      if (err) return res.status(500).json({ error: 'Помилка отримання талонів' });

      const today = new Date().toISOString().split('T')[0];

      try {
        const withQr = await Promise.all((vouchers || []).map(async (v) => {
          // generate QR image (cached)
          let qrImage = null;
          try { qrImage = await getQrImageCached(v.qr_code); } catch (e) { qrImage = null; }

          // check if used today
          const usedToday = await new Promise((resolve) => {
            db.get('SELECT * FROM voucher_usage WHERE voucher_id = ? AND used_date = ?', [v.id, today], (uErr, usageRow) => {
              if (uErr) return resolve(false);
              resolve(!!usageRow);
            });
          });

          // Compute expiration: if issued_at exists, expire after 9 hours from issuance
          // BUT if already used, don't show expiration time
          let isExpired = false;
          let expiresAt = null;
          const isUsed = (v.current_uses || 0) >= (v.max_uses || 1);
          
          if (!isUsed) {
            // Only calculate expiration for unused vouchers
            if (v.issued_at) {
              try {
                const issuedDt = new Date(v.issued_at);
                expiresAt = new Date(issuedDt.getTime() + 9 * 60 * 60 * 1000);
                isExpired = (new Date()) > expiresAt;
              } catch (e) {
                isExpired = !!(v.expires_date && v.expires_date < today);
              }
            } else {
              isExpired = !!(v.expires_date && v.expires_date < today);
            }
          } else {
            // Used vouchers are always "expired" (no longer valid)
            isExpired = true;
            expiresAt = null;
          }
          
          const usesRemaining = Math.max(0, (v.max_uses || 1) - (v.current_uses || 0));

          return {
            ...v,
            qrImage,
            usedToday,
            isExpired,
            isUsed,
            usesRemaining
          };
        }));
        // Sort: active (not expired and not used) first, then by created_date desc
        withQr.sort((a,b) => {
          const aActive = !a.isExpired && !a.isUsed;
          const bActive = !b.isExpired && !b.isUsed;
          if (aActive && !bActive) return -1;
          if (!aActive && bActive) return 1;
          // fallback: newer first
          return (b.created_date || '').localeCompare(a.created_date || '');
        });
        res.json(withQr);
      } catch (e) {
        res.json(vouchers || []);
      }
    }
  );
});

// Basic metrics (admin only)
app.get('/api/metrics', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  
  // Try cache first (10 sec TTL)
  const cached = await dbCache.cacheGet('metrics:counts');
  if (cached) {
    return res.json({ ...cached, fromCache: true });
  }

  db.serialize(() => {
    db.get('SELECT COUNT(*) as cnt FROM users', [], (e1, r1) => {
      db.get('SELECT COUNT(*) as cnt FROM vouchers', [], (e2, r2) => {
        db.get('SELECT COUNT(*) as cnt FROM voucher_usage', [], async (e3, r3) => {
          const result = { users: r1 ? r1.cnt : 0, vouchers: r2 ? r2.cnt : 0, voucher_usage: r3 ? r3.cnt : 0, timestamp: new Date().toISOString() };
          await dbCache.cacheSet('metrics:counts', result, 'metrics');
          res.json(result);
        });
      });
    });
  });
});

// Health endpoint
app.get('/api/health', (req, res) => {
  const pressure = getRuntimePressure();
  const overloadReason = getOverloadReason();
  res.json({
    status: overloadReason ? 'degraded' : 'ok',
    overloaded: Boolean(overloadReason),
    overloadReason,
    limits: {
      maxConcurrentRequests: MAX_CONCURRENT_REQUESTS,
      maxHeapUsedMb: MAX_HEAP_USED_MB,
      maxEventLoopP99LagMs: MAX_EVENT_LOOP_P99_LAG_MS
    },
    runtime: pressure,
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

// Readiness endpoint: returns 503 while overloaded so upstream can drain traffic.
app.get('/api/ready', (req, res) => {
  const overloadReason = getOverloadReason();
  if (overloadReason) {
    return res.status(503).json({ ready: false, overloadReason, timestamp: new Date().toISOString() });
  }
  return res.json({ ready: true, timestamp: new Date().toISOString() });
});

// Видати талон конкретному користувачу (1 раз на день, 1 використання)
app.post('/api/vouchers/distribute', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Доступ заборонений' });
  }

  const { user_id } = req.body;
  const today = new Date().toISOString().split('T')[0];

  if (!user_id) {
    return res.status(400).json({ error: 'Потрібно вказати користувача' });
  }

  // Перевірити, чи вже видано талон цьому користувачу сьогодні
  db.get(
    'SELECT * FROM vouchers WHERE user_id = ? AND created_date = ?',
    [user_id, today],
    async (err, existingVoucher) => {
      if (existingVoucher) {
        return res.status(400).json({ error: 'Користувач вже отримав талон на сьогодні' });
      }

      // Отримати дані користувача
      db.get('SELECT * FROM users WHERE id = ?', [user_id], async (err, user) => {
        if (err || !user) return res.status(404).json({ error: 'Користувач не знайдений' });

        const voucherId = uuidv4();
        const qrCode = uuidv4();

        try {
          const qrImage = await getQrImageCached(qrCode);

          const issuedAt = new Date().toISOString();
          db.run(
            'INSERT INTO vouchers (id, qr_code, user_id, student_name, created_date, expires_date, issued_at, max_uses, current_uses, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [voucherId, qrCode, user_id, user.name || user.username, today, null, issuedAt, 1, 0, 'active'],
            function(err) {
              if (err) return res.status(500).json({ error: 'Помилка видачі талону' });
              try { voucherCreatedCounter.inc(); } catch (e) {}
              res.json({ success: true, message: 'Талон видано користувачу', voucherId, qrCode, qrImage });
            }
          );
        } catch (err) {
          res.status(500).json({ error: 'Помилка створення QR-коду' });
        }
      });
    }
  );
});

// Видати талони ВСІМ зареєстрованим учням/вчителям (1 раз на день)
app.post('/api/vouchers/distribute-all', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Доступ заборонений' });
  }

  const today = new Date().toISOString().split('T')[0];
  db.all('SELECT id, username, name, role FROM users WHERE role IN ("student", "teacher")', [], async (err, users) => {
    if (err) return res.status(500).json({ error: 'Помилка отримання користувачів' });

    let created = 0;
    let skipped = 0;
    const results = [];

    for (const user of users) {
      // перевірити, чи вже видано сьогодні
      // eslint-disable-next-line no-await-in-loop
      const existing = await new Promise((resolve) => {
        db.get('SELECT id FROM vouchers WHERE user_id = ? AND created_date = ?', [user.id, today], (e, row) => resolve(row));
      });

      if (existing) {
        skipped++;
        results.push({ user: user.name || user.username, status: 'skipped' });
        continue;
      }

      const voucherId = uuidv4();
      const qrCode = uuidv4();
      try {
        // eslint-disable-next-line no-await-in-loop
        const qrImage = await getQrImageCached(qrCode);
        // eslint-disable-next-line no-await-in-loop
        await new Promise((resolve, reject) => {
          const issuedAt = new Date().toISOString();
          db.run(
            'INSERT INTO vouchers (id, qr_code, user_id, student_name, created_date, expires_date, issued_at, max_uses, current_uses, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [voucherId, qrCode, user.id, user.name || user.username, today, null, issuedAt, 1, 0, 'active'],
            (insertErr) => {
              if (insertErr) return reject(insertErr);
              try { voucherCreatedCounter.inc(); } catch (e) {}
              resolve();
            }
          );
        });
        created++;
        results.push({ user: user.name || user.username, status: 'created', voucherId, qrCode, qrImage });
      } catch (e) {
        results.push({ user: user.name || user.username, status: 'error', error: e.message });
      }
    }

    res.json({ success: true, created, skipped, results });
  });
});

// Створити новий талон (адміністратор ТІЛЬКИ)
app.post('/api/vouchers/create', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Доступ заборонений - тільки адміністратор' });
  }

  const { student_name, user_id, expires_date, max_uses } = req.body;
  const voucherId = uuidv4();
  const qrCode = uuidv4();
  const createdDate = new Date().toISOString().split('T')[0];
  const maxUsesValue = max_uses || 1;

  async function createVoucher() {
    try {
      const qrImage = await getQrImageCached(qrCode);

      const issuedAt = new Date().toISOString();
      db.run(
        'INSERT INTO vouchers (id, qr_code, user_id, student_name, created_date, expires_date, issued_at, max_uses, current_uses, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [voucherId, qrCode, user_id, student_name, createdDate, expires_date || null, issuedAt, maxUsesValue, 0, 'active'],
        function(err) {
          if (err) return res.status(500).json({ error: 'Помилка створення талону' });
          try { voucherCreatedCounter.inc(); } catch (e) {}
          res.json({ success: true, voucherId, qrCode, qrImage });
        }
      );
    } catch (err) {
      res.status(500).json({ error: 'Помилка створення QR-коду' });
    }
  }
  
  createVoucher();
});

// Отримати талон за QR-кодом (для перевірки)
app.get('/api/vouchers/check/:qrCode', (req, res) => {
  const raw = req.params.qrCode || '';
  let qrCode = decodeURIComponent(raw).trim();

  // If the scanned payload is a URL or contains extra text, try to extract a UUID-like token
  const uuidMatch = qrCode.match(/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/);
  if (uuidMatch) qrCode = uuidMatch[0];

  // Primary exact lookup
  function respondWithVoucher(voucher) {
    if (!voucher) return res.status(404).json({ error: 'Талон не знайдений' });

    const today = new Date().toISOString().split('T')[0];
    db.get('SELECT * FROM voucher_usage WHERE voucher_id = ? AND used_date = ?', [voucher.id, today], (err, usage) => {
      const isExpiredByDate = voucher.expires_date && voucher.expires_date < new Date().toISOString().split('T')[0];
      const isExpiredBy9Hours = isVoucherExpired(voucher);
      const isExpired = isExpiredByDate || isExpiredBy9Hours;
      const isExhausted = voucher.current_uses >= voucher.max_uses;
      
      // Add human-readable expiry message
      let expiresMessage = null;
      if (isExpiredBy9Hours) {
        expiresMessage = '⏰ Строк дії талона минув (діяв 9 годин від видачі)';
      } else if (voucher.expires_date) {
        if (voucher.expires_date === today) {
          expiresMessage = 'Діє до 24:00 сьогодні';
        } else {
          expiresMessage = `Діє до ${voucher.expires_date}`;
        }
      }

      res.json({
        ...voucher,
        // Treat fully-used vouchers as "used" for scanner UI compatibility.
        usedToday: !!usage || isExhausted,
        isExpired,
        isExhausted,
        usesRemaining: Math.max(0, voucher.max_uses - voucher.current_uses),
        expiresMessage
      });
    });
  }

  db.get('SELECT v.*, u.name, COALESCE(c.name, NULL) as class_name FROM vouchers v LEFT JOIN users u ON v.user_id = u.id LEFT JOIN classes c ON u.class_id = c.id WHERE v.qr_code = ?', [qrCode], (err, voucher) => {
    if (err) return res.status(500).json({ error: 'Помилка перевірки' });
    if (voucher) return respondWithVoucher(voucher);

    // Fallback: try fuzzy match where qr_code may be stored with prefixes/suffixes
    db.get('SELECT v.*, u.name, COALESCE(c.name, NULL) as class_name FROM vouchers v LEFT JOIN users u ON v.user_id = u.id LEFT JOIN classes c ON u.class_id = c.id WHERE v.qr_code LIKE ?', [`%${qrCode}%`], (err2, voucher2) => {
      if (err2) return res.status(500).json({ error: 'Помилка перевірки' });
      return respondWithVoucher(voucher2);
    });
  });
});

// Позначити талон як використаний (на касі)
app.post('/api/vouchers/use', authenticateToken, (req, res) => {
  if (req.user.role !== 'cashier' && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Доступ заборонений' });
  }

  const { qrCode, studentId, studentName } = req.body;
  const today = new Date().toISOString().split('T')[0];
  const now = new Date().toTimeString().split(' ')[0];

  db.get('SELECT * FROM vouchers WHERE qr_code = ?', [qrCode], (err, voucher) => {
    if (err || !voucher) return res.status(404).json({ error: 'Талон не знайдений' });
    // Ensure voucher is active
    if (voucher.status !== 'active') return res.status(400).json({ error: 'Талон недоступний' });

    // Перевірити, чи минув 9-годинний строк дії від часу видачі
    if (isVoucherExpired(voucher)) {
      return res.status(400).json({ error: '⏰ Талон закінчився (діяв 9 годин від видачі)' });
    }

    // Перевірити, чи вже використаний сьогодні
    db.get(
      'SELECT * FROM voucher_usage WHERE voucher_id = ? AND used_date = ?',
      [voucher.id, today],
      (err, usage) => {
        if (usage) {
          return res.status(400).json({ error: 'Талон уже використаний сьогодні' });
        }

        // --- Prevent resale: require owner verification ---
        if (!studentId && !studentName) {
          return res.status(400).json({ error: 'Потрібно підтвердити власника талону (studentId або studentName)' });
        }
        if (studentId && studentId !== voucher.user_id) {
          return res.status(403).json({ error: 'Талон не належить вказаному учню' });
        }
        if (!studentId && studentName) {
          const cleanGiven = String(studentName || '').trim().toLowerCase();
          const cleanStored = String(voucher.student_name || '').trim().toLowerCase();
          if (cleanGiven !== cleanStored) {
            return res.status(403).json({ error: 'Ім\'я учня не збігається з власником талону' });
          }
        }

        // Перевірити, чи залишилися використання
        if (voucher.current_uses >= voucher.max_uses) {
          return res.status(400).json({ error: `Талон вже використаний (${voucher.current_uses}/${voucher.max_uses})` });
        }

        const usageId = uuidv4();
        db.run(
          'INSERT INTO voucher_usage (id, voucher_id, used_date, used_time, cashier_id) VALUES (?, ?, ?, ?, ?)',
          [usageId, voucher.id, today, now, req.user.id],
          (err) => {
            if (err) return res.status(500).json({ error: 'Помилка реєстрації використання' });
            
            // Збільшити лічильник використання
            db.run(
              'UPDATE vouchers SET current_uses = current_uses + 1 WHERE id = ?',
              [voucher.id],
              (updateErr) => {
                // Fetch updated voucher data to return current state
                db.get('SELECT * FROM vouchers WHERE id = ?', [voucher.id], (fetchErr, updatedVoucher) => {
                  if (fetchErr || !updatedVoucher) {
                    const nextUses = Number(voucher.current_uses || 0) + 1;
                    const maxUses = Number(voucher.max_uses || 1);
                    return res.json({ 
                      success: true, 
                      message: 'Талон позначено як використаний', 
                      voucher: voucher.student_name,
                      usesRemaining: Math.max(0, maxUses - nextUses),
                      updatedVoucher: {
                        ...voucher,
                        current_uses: nextUses,
                        usedToday: true,
                        isUsed: nextUses >= maxUses,
                        isExhausted: nextUses >= maxUses,
                        isExpired: true,
                        expiresAt: null
                      }
                    });
                  }

                  // Compute isUsed and isExpired for updated voucher
                  const isUsed = (updatedVoucher.current_uses || 0) >= (updatedVoucher.max_uses || 1);
                  let isExpired = isUsed ? true : false; // Used vouchers are expired
                  let expiresAt = isUsed ? null : null; // No expiration time for used vouchers
                  
                  if (!isUsed && updatedVoucher.issued_at) {
                    try {
                      const issuedDt = new Date(updatedVoucher.issued_at);
                      expiresAt = new Date(issuedDt.getTime() + 9 * 60 * 60 * 1000);
                      isExpired = (new Date()) > expiresAt;
                    } catch (e) {
                      isExpired = !!(updatedVoucher.expires_date && updatedVoucher.expires_date < today);
                    }
                  }

                  res.json({ 
                    success: true, 
                    message: 'Талон позначено як використаний', 
                    voucher: updatedVoucher.student_name,
                    usesRemaining: Math.max(0, updatedVoucher.max_uses - updatedVoucher.current_uses),
                    updatedVoucher: {
                      ...updatedVoucher,
                      usedToday: true,
                      isUsed,
                      isExhausted: isUsed,
                      isExpired,
                      expiresAt: expiresAt ? expiresAt.toISOString() : null
                    }
                  });
                });
              }
            );
          }
        );
      }
    );
  });
});

// Отримати всі талони (для адміна ТІЛЬКИ)
app.get('/api/vouchers/all', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Доступ заборонений - тільки адміністратор' });
  }

  const { status } = req.query; // 'active', 'used', 'expired'
  let query = 'SELECT v.*, u.username as owner_username, u.name as owner_name, (SELECT COUNT(*) FROM voucher_usage WHERE voucher_id = v.id) as total_used FROM vouchers v LEFT JOIN users u ON v.user_id = u.id';
  let params = [];

  if (status === 'active') {
    query += ' WHERE v.current_uses < v.max_uses AND (v.expires_date IS NULL OR v.expires_date >= date("now"))';
  } else if (status === 'used') {
    query += ' WHERE v.current_uses >= v.max_uses';
  } else if (status === 'expired') {
    query += ' WHERE v.expires_date IS NOT NULL AND v.expires_date < date("now")';
  }

  query += ' ORDER BY v.created_date DESC LIMIT 1000';

  db.all(query, params, (err, vouchers) => {
    if (err) return res.status(500).json({ error: 'Помилка отримання талонів' });
    try {
      const now = new Date();
      const processed = (vouchers || []).map((v) => {
        const isUsed = (v.current_uses || 0) >= (v.max_uses || 1);
        let isExpired = false;
        let expiresAt = null;
        
        if (!isUsed) {
          // Only calculate expiration for unused vouchers
          if (v.issued_at) {
            try {
              const issuedDt = new Date(v.issued_at);
              expiresAt = new Date(issuedDt.getTime() + 9 * 60 * 60 * 1000);
              isExpired = now > expiresAt;
            } catch (e) {
              isExpired = !!(v.expires_date && v.expires_date < new Date().toISOString().split('T')[0]);
            }
          } else {
            isExpired = !!(v.expires_date && v.expires_date < new Date().toISOString().split('T')[0]);
          }
        } else {
          // Used vouchers are always "expired" (no longer valid)
          isExpired = true;
          expiresAt = null;
        }
        
        return { ...v, isExpired, isUsed, expiresAt: expiresAt ? expiresAt.toISOString() : null };
      });
      res.json(processed);
    } catch (e) {
      res.json(vouchers || []);
    }
  });
});

// Отримати талони конкретного користувача (для адміна ТІЛЬКИ)
app.get('/api/vouchers/user/:userId', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Доступ заборонений - тільки адміністратор' });
  }
  const userId = req.params.userId;
  const today = new Date().toISOString().split('T')[0];

  db.all('SELECT * FROM vouchers WHERE user_id = ? ORDER BY created_date DESC', [userId], async (err, vouchers) => {
    if (err) return res.status(500).json({ error: 'Помилка отримання талонів' });

    try {
      const withComputed = await Promise.all((vouchers || []).map(async (v) => {
        let qrImage = null;
        try { qrImage = await getQrImageCached(v.qr_code); } catch (e) { qrImage = null; }
        const usedToday = await new Promise((resolve) => {
          db.get('SELECT * FROM voucher_usage WHERE voucher_id = ? AND used_date = ?', [v.id, today], (uErr, usageRow) => {
            if (uErr) return resolve(false);
            resolve(!!usageRow);
          });
        });
        const isUsed = (v.current_uses || 0) >= (v.max_uses || 1);
        // Compute expiration: used vouchers are always treated as not active.
        let isExpired = false;
        let expiresAt = null;
        if (isUsed) {
          isExpired = true;
        } else if (v.issued_at) {
          try {
            const issuedDt = new Date(v.issued_at);
            expiresAt = new Date(issuedDt.getTime() + 9 * 60 * 60 * 1000);
            isExpired = (new Date()) > expiresAt;
          } catch (e) {
            isExpired = !!(v.expires_date && v.expires_date < today);
          }
        } else {
          isExpired = !!(v.expires_date && v.expires_date < today);
        }
        const usesRemaining = Math.max(0, (v.max_uses || 1) - (v.current_uses || 0));
        return {
          ...v,
          qrImage,
          usedToday: usedToday || isUsed,
          isExpired,
          isUsed,
          isExhausted: isUsed,
          usesRemaining,
          expiresAt: expiresAt ? expiresAt.toISOString() : null
        };
      }));
      res.json(withComputed);
    } catch (e) {
      res.json(vouchers || []);
    }
  });
});

// Видалити талон (адмін)
app.delete('/api/vouchers/:id', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Доступ заборонений' });
  const id = req.params.id;

  db.serialize(() => {
    db.run('DELETE FROM voucher_usage WHERE voucher_id = ?', [id], (uErr) => {
      if (uErr) return res.status(500).json({ error: 'Помилка при видаленні використань' });
      db.run('DELETE FROM vouchers WHERE id = ?', [id], function(vErr) {
        if (vErr) return res.status(500).json({ error: 'Помилка при видаленні талону' });
        res.json({ success: true, deleted: this.changes || 0 });
      });
    });
  });
});

// Отримати статистику використання (для адміна ТІЛЬКИ)
app.get('/api/stats', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Доступ заборонений - тільки адміністратор' });
  }

  db.all(
    `SELECT u.id, u.name, COALESCE(c.name, '(Без класу)') as class_name,
            COUNT(v.id) as total_vouchers,
            COALESCE(SUM(v.current_uses), 0) as total_uses,
            SUM(CASE WHEN v.current_uses < v.max_uses AND (v.expires_date IS NULL OR v.expires_date >= date('now')) THEN 1 ELSE 0 END) as remaining
     FROM users u 
     LEFT JOIN classes c ON u.class_id = c.id
     LEFT JOIN vouchers v ON u.id = v.user_id 
     WHERE u.role = 'student' 
     GROUP BY u.id, u.name, c.name
     ORDER BY COALESCE(c.name, ''), u.name ASC`,
    [],
    (err, stats) => {
      if (err) return res.status(500).json({ error: 'Помилка отримання статистики' });
      res.json(stats);
    }
  );
});

// --- Cleanup task: remove vouchers (and their usage) one day after last use ---
const CLEANUP_INTERVAL_MS = parseInt(process.env.CLEANUP_INTERVAL_MS || String(60 * 60 * 1000), 10); // default: every hour
const CLEANUP_AGE_SQL = process.env.CLEANUP_AGE_SQL || "datetime('now','-1 day')"; // SQL expression for cutoff

function cleanupOldVouchers() {
  try {
    // Find voucher ids whose latest usage created_at is older than cutoff
    const sql = `SELECT voucher_id FROM voucher_usage GROUP BY voucher_id HAVING MAX(created_at) <= ${CLEANUP_AGE_SQL}`;
    db.all(sql, [], (err, rows) => {
      if (err) {
        console.error('❌ Cleanup: failed to query old voucher_usage:', err);
        return;
      }
      if (!rows || rows.length === 0) return;
      const ids = rows.map(r => r.voucher_id);
      console.log(`🧹 Cleanup: removing ${ids.length} vouchers last-used before ${CLEANUP_AGE_SQL}`);

      // Use db.run() instead of db.prepare() for compatibility
      ids.forEach((vid) => {
        db.run('DELETE FROM voucher_usage WHERE voucher_id = ?', [vid], (uErr) => {
          if (uErr) console.error('❌ Cleanup: failed to delete voucher_usage for', vid, uErr);
        });
        db.run('DELETE FROM vouchers WHERE id = ?', [vid], (vErr) => {
          if (vErr) console.error('❌ Cleanup: failed to delete voucher', vid, vErr);
        });
      });
    });
  } catch (e) {
    console.error('❌ Cleanup: unexpected error', e);
  }
}

// Run cleanup at startup and then periodically
setImmediate(() => {
  try { cleanupOldVouchers(); } catch (e) { console.error('❌ Initial cleanup error', e); }
  try { markExpiredVouchersAsUsed(); } catch (e) { console.error('❌ Initial expiration check error', e); }
  try { cleanupExpiredRefreshTokens(); } catch (e) { console.error('❌ Initial refresh token cleanup error', e); }
});
setInterval(() => {
  cleanupOldVouchers();
}, CLEANUP_INTERVAL_MS);

setInterval(() => {
  cleanupExpiredRefreshTokens();
}, 60 * 60 * 1000);

// Run expiration check every 5 minutes
setInterval(() => {
  try { markExpiredVouchersAsUsed(); } catch (e) { console.error('❌ Expiration check error', e); }
}, 5 * 60 * 1000);


// ========== ATTENDANCE MANAGEMENT ==========

// Отримати всіх учнів зі статусом присутності
app.get('/api/users/attendance', authenticateToken, (req, res) => {
  // Admin and cashier can list all students. Teacher can list students in their class.
  const kyivTime = new Date(new Date().toLocaleString('en-US', { timeZone: 'Europe/Kyiv' }));
  const today = kyivTime.toISOString().split('T')[0];
  
  if (req.user.role === 'teacher') {
    // find teacher's class
    db.get('SELECT id FROM classes WHERE teacher_id = ?', [req.user.id], (err, classRow) => {
      if (err) return res.status(500).json({ error: 'Помилка отримання даних вчителя' });
      if (!classRow) return res.status(403).json({ error: "Вчитель не прив'язаний до класу" });
      
      const classId = classRow.id;
      // Get students and their attendance for today
      db.all(
        `SELECT u.id, u.name, u.username, u.email, u.role, 
                COALESCE(a.status, 'absent') as status, a.attendance_date
         FROM users u
         LEFT JOIN attendance a ON u.id = a.student_id AND a.attendance_date = ?
         WHERE u.role = "student" AND u.class_id = ? 
         ORDER BY u.name ASC`,
        [today, classId],
        (e, students) => {
          if (e) return res.status(500).json({ error: 'Помилка отримання учнів' });
          res.json(students || []);
        }
      );
    });
    return;
  }

  if (!['admin', 'cashier'].includes(req.user.role)) {
    return res.status(403).json({ error: 'Доступ заборонений' });
  }

  // Get all students and their attendance for today
  db.all(
    `SELECT u.id, u.name, u.username, u.email, u.role, 
            COALESCE(a.status, 'absent') as status, a.attendance_date
     FROM users u
     LEFT JOIN attendance a ON u.id = a.student_id AND a.attendance_date = ?
     WHERE u.role = 'student'
     ORDER BY u.name ASC`,
    [today],
    (err, students) => {
      if (err) return res.status(500).json({ error: 'Помилка отримання учнів' });
      res.json(students || []);
    }
  );
});

// Позначити присутність учнів (передати масив ID)
app.post('/api/users/attendance/set', authenticateToken, (req, res) => {
  const { userIds } = req.body;
  
  if (!Array.isArray(userIds) || userIds.length === 0) {
    return res.status(400).json({ error: 'userIds має бути непустий масив' });
  }

  const kyivTime = new Date(new Date().toLocaleString('en-US', { timeZone: 'Europe/Kyiv' }));
  const today = kyivTime.toISOString().split('T')[0];
  
  console.log(`\n[ATTENDANCE SET] POST request received for marking presence`);
  console.log(`[ATTENDANCE SET] Today's date (Kyiv): ${today}`);
  console.log(`[ATTENDANCE SET] User IDs to mark present:`, userIds);

  // Helper function to create voucher for a student
  const createVoucherIfNotExists = (studentId, studentName) => {
    db.get(
      'SELECT id FROM vouchers WHERE user_id = ? AND created_date = ?',
      [studentId, today],
      (checkErr, existing) => {
        if (checkErr) {
          console.error(`Error checking voucher for ${studentName}:`, checkErr);
          return;
        }
        
        if (!existing) {
          const voucherId = require('uuid').v4();
          const qrCode = require('uuid').v4();
          const issuedAt = new Date().toISOString();
          db.run(
            'INSERT INTO vouchers (id, qr_code, user_id, student_name, created_date, issued_at, max_uses, current_uses, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [voucherId, qrCode, studentId, studentName, today, issuedAt, 1, 0, 'active'],
            (insertErr) => {
              if (insertErr) {
                // Constraint violation (duplicate voucher) is acceptable - ignore
                if (!insertErr.message.includes('UNIQUE')) {
                  console.error(`Error creating voucher for ${studentName}:`, insertErr);
                }
              } else {
                console.log(`✓ Voucher auto-created for ${studentName} (marked present after 9:15 AM) - issued_at: ${issuedAt}`);
              }
            }
          );
        }
      }
    );
  };

  if (req.user.role === 'teacher') {
    db.get('SELECT id FROM classes WHERE teacher_id = ?', [req.user.id], (err, classRow) => {
      if (err) return res.status(500).json({ error: 'Помилка перевірки вчителя' });
      if (!classRow) return res.status(403).json({ error: "Вчитель не прив'язаний до класу" });
      const classId = classRow.id;
      
      const placeholdersCheck = userIds.map(() => '?').join(',');
      db.all(`SELECT id, name FROM users WHERE id IN (${placeholdersCheck}) AND role = 'student' AND class_id = ?`, [...userIds, classId], (e, rows) => {
        if (e) return res.status(500).json({ error: 'Помилка перевірки учнів' });
        const validRows = rows || [];
        if (validRows.length !== userIds.length) return res.status(403).json({ error: 'Один або кілька учнів не належать до вашого класу' });
        
        const validIds = validRows.map(r => r.id);
        
        // Process students sequentially to ensure all records are saved
        const processNextStudent = (idx) => {
          if (idx >= validIds.length) {
            res.json({ success: true, updated: validIds.length });
            return;
          }
          
          const studentId = validIds[idx];
          const studentName = validRows[idx].name;
          
          // Check if attendance record exists for today
          db.get(
            'SELECT id FROM attendance WHERE student_id = ? AND attendance_date = ?',
            [studentId, today],
            (checkErr, existingRow) => {
              if (checkErr) {
                console.error('Error checking attendance:', checkErr);
                processNextStudent(idx + 1);
              } else if (existingRow) {
                // Update existing record
                console.log(`[ATTENDANCE] Updating: attendance_id=${existingRow.id}, student=${studentId}, status=present`);
                db.run(
                  'UPDATE attendance SET status = ? WHERE id = ?',
                  ['present', existingRow.id],
                  (updateErr) => {
                    if (!updateErr) {
                      console.log(`[ATTENDANCE] ✓ Successfully updated attendance for student ${studentId}`);
                      createVoucherIfNotExists(studentId, studentName);
                    } else {
                      console.error(`[ATTENDANCE] ✗ Error updating attendance:`, updateErr);
                    }
                    processNextStudent(idx + 1);
                  }
                );
              } else {
                // Insert new record
                const attendanceId = require('uuid').v4();
                const sql = 'INSERT INTO attendance (id, student_id, class_id, attendance_date, status) VALUES (?, ?, ?, ?, ?)';
                const params = [attendanceId, studentId, classId, today, 'present'];
                console.log(`[ATTENDANCE INSERT] SQL: ${sql}`);
                console.log(`[ATTENDANCE INSERT] Params: [${attendanceId}, ${studentId}, ${classId}, "${today}", "present"]`);
                db.run(sql, params, (insertErr) => {
                  if (insertErr) {
                    // If UNIQUE constraint violation, just update instead
                    if (insertErr.message.includes('UNIQUE')) {
                      console.log(`[ATTENDANCE INSERT] UNIQUE constraint violation - updating instead`);
                      db.run(
                        'UPDATE attendance SET status = ? WHERE student_id = ? AND attendance_date = ?',
                        ['present', studentId, today],
                        (updateErr) => {
                          if (!updateErr) {
                            console.log(`[ATTENDANCE INSERT] ✓ Updated via constraint handler for student ${studentId}`);
                            createVoucherIfNotExists(studentId, studentName);
                          }
                          processNextStudent(idx + 1);
                        }
                      );
                    } else {
                      console.error(`[ATTENDANCE INSERT] ✗ Error inserting attendance:`, insertErr);
                      processNextStudent(idx + 1);
                    }
                  } else {
                    // Verify the record was inserted
                    db.get(
                      'SELECT * FROM attendance WHERE id = ?',
                      [attendanceId],
                      (verifyErr, record) => {
                        if (verifyErr) {
                          console.error(`[ATTENDANCE INSERT] ✗ Verification error:`, verifyErr);
                        } else {
                          console.log(`[ATTENDANCE INSERT] ✓ Record verified:`, record);
                        }
                        console.log(`[ATTENDANCE INSERT] ✓ Successfully inserted attendance for student ${studentId} on date "${today}"`);
                        createVoucherIfNotExists(studentId, studentName);
                        processNextStudent(idx + 1);
                      }
                    );
                  }
                });
              }
            }
          );
        };
        
        processNextStudent(0);
      });
    });
    return;
  }

  if (!['admin', 'cashier'].includes(req.user.role)) {
    return res.status(403).json({ error: 'Доступ заборонений' });
  }

  const placeholders = userIds.map(() => '?').join(',');
  db.all(
    `SELECT id, name FROM users WHERE id IN (${placeholders}) AND role = 'student'`,
    userIds,
    (err, students) => {
      if (err) return res.status(500).json({ error: 'Помилка перевірки учнів' });
      
      // Process students sequentially to ensure all records are saved
      const processNextStudent = (idx) => {
        if (idx >= (students || []).length) {
          res.json({ success: true, updated: (students || []).length });
          return;
        }
        
        const student = (students || [])[idx];
        
        // Check if attendance record exists for today
        db.get(
          'SELECT id FROM attendance WHERE student_id = ? AND attendance_date = ?',
          [student.id, today],
          (checkErr, existingRow) => {
            if (checkErr) {
              console.error('Error checking attendance:', checkErr);
              processNextStudent(idx + 1);
            } else if (existingRow) {
              // Update existing record
              db.run(
                'UPDATE attendance SET status = ? WHERE id = ?',
                ['present', existingRow.id],
                (updateErr) => {
                  if (!updateErr) {
                    createVoucherIfNotExists(student.id, student.name);
                  } else {
                    console.error('Error updating attendance:', updateErr);
                  }
                  processNextStudent(idx + 1);
                }
              );
            } else {
              // Insert new record
              db.run(
                'INSERT INTO attendance (id, student_id, attendance_date, status) VALUES (?, ?, ?, ?)',
                [require('uuid').v4(), student.id, today, 'present'],
                (insertErr) => {
                  if (!insertErr) {
                    createVoucherIfNotExists(student.id, student.name);
                  } else {
                    console.error('Error inserting attendance:', insertErr);
                  }
                  processNextStudent(idx + 1);
                }
              );
            }
          }
        );
      };
      
      processNextStudent(0);
    }
  );
});

// Знімати присутність учня
app.post('/api/users/attendance/unset', authenticateToken, (req, res) => {
  const { userIds } = req.body;
  if (!Array.isArray(userIds) || userIds.length === 0) {
    return res.status(400).json({ error: 'userIds має бути непустий масив' });
  }

  const kyivTime = new Date(new Date().toLocaleString('en-US', { timeZone: 'Europe/Kyiv' }));
  const today = kyivTime.toISOString().split('T')[0];

  if (req.user.role === 'teacher') {
    db.get('SELECT id FROM classes WHERE teacher_id = ?', [req.user.id], (err, classRow) => {
      if (err) return res.status(500).json({ error: 'Помилка перевірки вчителя' });
      if (!classRow) return res.status(403).json({ error: "Вчитель не прив'язаний до класу" });
      const classId = classRow.id;
      const placeholdersCheck = userIds.map(() => '?').join(',');
      db.all(`SELECT id FROM users WHERE id IN (${placeholdersCheck}) AND role = 'student' AND class_id = ?`, [...userIds, classId], (e, rows) => {
        if (e) return res.status(500).json({ error: 'Помилка перевірки учнів' });
        const validIds = (rows || []).map(r => r.id);
        if (validIds.length !== userIds.length) return res.status(403).json({ error: 'Один або кілька учнів не належать до вашого класу' });
        const placeholders = validIds.map(() => '?').join(',');
        
        // 1. Видалити attendance запис
        db.run(`DELETE FROM attendance WHERE student_id IN (${placeholders}) AND attendance_date = ?`, [...validIds, today], function(updErr) {
          if (updErr) {
            console.error('Error deleting attendance:', updErr);
            return res.status(500).json({ error: 'Помилка зняття присутності' });
          }
          
          // 2. Видалити талон за цей день
          db.run(`DELETE FROM vouchers WHERE user_id IN (${placeholders}) AND created_date = ?`, [...validIds, today], function(voucherErr) {
            if (voucherErr) {
              console.error('Error deleting voucher:', voucherErr);
              // Not fatal - continue
            }
            res.json({ success: true, updated: this.changes || 0 });
          });
        });
      });
    });
    return;
  }

  if (!['admin', 'cashier'].includes(req.user.role)) {
    return res.status(403).json({ error: 'Доступ заборонений' });
  }

  const placeholders = userIds.map(() => '?').join(',');
  
  // 1. Видалити attendance запис
  db.run(
    `DELETE FROM attendance WHERE student_id IN (${placeholders}) AND attendance_date = ?`,
    [...userIds, today],
    function(err) {
      if (err) {
        console.error('Error deleting attendance:', err);
        return res.status(500).json({ error: 'Помилка зняття присутності' });
      }
      
      // 2. Видалити талон за цей день
      db.run(
        `DELETE FROM vouchers WHERE user_id IN (${placeholders}) AND created_date = ?`,
        [...userIds, today],
        function(voucherErr) {
          if (voucherErr) {
            console.error('Error deleting voucher:', voucherErr);
            // Not fatal - continue
          }
          res.json({ success: true, updated: this.changes || 0 });
        }
      );
    }
  );
});

// ========== ADMIN CONFIGURATION MANAGEMENT ==========

// Отримати всі налаштування
app.get('/api/admin/config', authenticateToken, (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Тільки адміністратор' });
    }

    console.log('📥 GET /api/admin/config - fetching all settings...');
    const settings = adminConfig.getAllConfigurableSettings();
    
    if (!settings || typeof settings !== 'object') {
      console.error('❌ getAllConfigurableSettings returned invalid data:', typeof settings);
      return res.status(500).json({ error: 'Invalid settings data' });
    }
    
    console.log(`✓ Successfully returned settings with ${Object.keys(settings).length} categories`);
    res.json(settings);
  } catch (err) {
    console.error('❌ Error in GET /api/admin/config:', err.message);
    console.error(err.stack);
    res.status(500).json({ error: 'Помилка завантаження налаштувань: ' + err.message });
  }
});

// Оновити кілька налаштувань за раз (MUST BE BEFORE :key route!)
app.post('/api/admin/config/bulk-update', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Тільки адміністратор' });
  }

  const { settings } = req.body;

  if (!Array.isArray(settings) || settings.length === 0) {
    return res.status(400).json({ error: 'Потрібен масив налаштувань' });
  }

  const results = [];
  const errors = [];

  for (const setting of settings) {
    const { key, value, type } = setting;
    
    if (!key || value === undefined) {
      errors.push({ key, error: 'Потрібні key та value' });
      continue;
    }

    try {
      await adminConfig.saveConfigValue(db, key, value, type, req.user.id);
      results.push({ key, value, status: 'success' });
    } catch (err) {
      errors.push({ key, error: err.message });
    }
  }

  logAudit(req.user.id, 'config_bulk_updated', req, { updated: results.length, failed: errors.length });

  res.json({ 
    success: errors.length === 0,
    updated: results,
    errors,
    total: settings.length
  });
});

// Отримати поточне значення налаштування
app.get('/api/admin/config/:key', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Тільки адміністратор' });
  }

  const { key } = req.params;
  const value = adminConfig.getRuntimeConfigValue(key);
  
  if (value === undefined) {
    return res.status(404).json({ error: 'Налаштування не знайдено' });
  }

  res.json({ key, value });
});

// Оновити налаштування
app.post('/api/admin/config/:key', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Тільки адміністратор' });
  }

  const { key } = req.params;
  const { value, type } = req.body;

  if (!key || value === undefined) {
    return res.status(400).json({ error: 'Потрібні key та value' });
  }

  try {
    await adminConfig.saveConfigValue(db, key, value, type, req.user.id);
    
    // Логування акції
    logAudit(req.user.id, 'config_updated', req, { key, value });
    
    res.json({ success: true, key, value, message: 'Налаштування оновлено' });
  } catch (err) {
    console.error('Error saving config:', err);
    res.status(500).json({ error: 'Помилка збереження налаштування' });
  }
});

// Отримати всі налаштування для адміна
app.get('/api/admin/all-config', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Тільки адміністратор' });
  }

  const runtimeConfig = adminConfig.getAllRuntimeConfig();
  const defaults = adminConfig.getAllConfigurableSettings();

  res.json({
    runtime: runtimeConfig,
    defaults: defaults,
    lastUpdated: new Date().toISOString()
  });
});

// Бекап налаштувань - скачати як JSON
app.get('/api/admin/config/backup/download', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Тільки адміністратор' });
  }

  try {
    const runtimeConfig = adminConfig.getAllRuntimeConfig();
    const settings = adminConfig.getAllConfigurableSettings();
    
    const backup = {
      timestamp: new Date().toISOString(),
      version: '1.0',
      app_name: 'Шкільні талони',
      database: process.env.DATABASE_URL ? 'PostgreSQL' : 'SQLite',
      currentValues: runtimeConfig,
      schema: settings
    };

    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename=school-vouchers-settings-${new Date().toISOString().split('T')[0]}.json`);
    res.json(backup);

    logAudit(req.user.id, 'config_backup_downloaded', req, {});
  } catch (err) {
    console.error('Error creating backup:', err);
    res.status(500).json({ error: 'Помилка створення бекапу: ' + err.message });
  }
});

// Відновити налаштування з бекапу
app.post('/api/admin/config/restore', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Тільки адміністратор' });
  }

  try {
    const { currentValues, settings: backupSettings } = req.body;

    if (!currentValues && !backupSettings) {
      return res.status(400).json({ error: 'Статус: Потрібні currentValues або settings' });
    }

    const results = [];
    const errors = [];
    const valuesToRestore = currentValues || {};

    // If backup has schema format with settings
    if (backupSettings && typeof backupSettings === 'object') {
      for (const category in backupSettings) {
        if (backupSettings[category] && backupSettings[category].settings && Array.isArray(backupSettings[category].settings)) {
          for (const setting of backupSettings[category].settings) {
            const key = setting.key;
            const value = valuesToRestore[key] !== undefined ? valuesToRestore[key] : setting.default;
            
            try {
              await new Promise((resolve, reject) => {
                adminConfig.saveConfigValue(db, key, value, setting.type, req.user.id, (err) => {
                  if (err) reject(err);
                  else resolve();
                });
              });
              results.push({ key, status: 'restored' });
            } catch (err) {
              console.error(`Error restoring setting ${key}:`, err);
              errors.push({ key, error: err.message });
            }
          }
        }
      }
    } else if (valuesToRestore && typeof valuesToRestore === 'object') {
      // Direct key-value restore
      for (const key in valuesToRestore) {
        try {
          const value = valuesToRestore[key];
          await new Promise((resolve, reject) => {
            const settingDefinition = adminConfig.getSettingDefinition(key);
            adminConfig.saveConfigValue(db, key, value, settingDefinition?.type, req.user.id, (err) => {
              if (err) reject(err);
              else resolve();
            });
          });
          results.push({ key, status: 'restored' });
        } catch (err) {
          console.error(`Error restoring setting ${key}:`, err);
          errors.push({ key, error: err.message });
        }
      }
    }

    logAudit(req.user.id, 'config_restored', req, { restored: results.length, failed: errors.length });

    res.json({
      success: errors.length === 0,
      restored: results.length,
      failed: errors.length,
      results,
      errors,
      message: `✓ Відновлено ${results.length} налаштувань${errors.length > 0 ? `, помилок: ${errors.length}` : ''}`
    });
  } catch (err) {
    console.error('Error restoring settings:', err);
    res.status(500).json({ error: 'Помилка відновлення налаштувань: ' + err.message });
  }
});

// Скинути налаштування на стандартні
app.post('/api/admin/config/reset-to-defaults', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Тільки адміністратор' });
  }

  try {
    const settings = adminConfig.getAllConfigurableSettings();
    const results = [];
    const errors = [];

    for (const category in settings) {
      if (settings[category] && settings[category].settings && Array.isArray(settings[category].settings)) {
        for (const setting of settings[category].settings) {
          try {
            await new Promise((resolve, reject) => {
              adminConfig.saveConfigValue(db, setting.key, setting.default, setting.type, req.user.id, (err) => {
                if (err) reject(err);
                else resolve();
              });
            });
            results.push({ key: setting.key, value: setting.default, status: 'reset' });
          } catch (err) {
            console.error(`Error resetting ${setting.key}:`, err);
            errors.push({ key: setting.key, error: err.message });
          }
        }
      }
    }

    logAudit(req.user.id, 'config_reset_to_defaults', req, { reset: results.length, failed: errors.length });

    res.json({
      success: errors.length === 0,
      reset: results.length,
      failed: errors.length,
      results,
      errors,
      message: `✓ Скинуто ${results.length} налаштувань на стандартні${errors.length > 0 ? `, помилок: ${errors.length}` : ''}`
    });
  } catch (err) {
    console.error('Error resetting settings:', err);
    res.status(500).json({ error: 'Помилка скидання налаштувань: ' + err.message });
  }
});

// Очистити всіх від присутності (на початок дня)
app.post('/api/users/attendance/clear-all', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Тільки адміністратор' });
  }

  const kyivTime = new Date(new Date().toLocaleString('en-US', { timeZone: 'Europe/Kyiv' }));
  const today = kyivTime.toISOString().split('T')[0];

  // 1. Видалити attendance записи
  db.run(
    `DELETE FROM attendance WHERE attendance_date = ?`,
    [today],
    function(err) {
      if (err) {
        console.error('Error clearing attendance:', err);
        return res.status(500).json({ error: 'Помилка очищення присутності' });
      }
      
      // 2. Видалити талони за цей день
      db.run(
        `DELETE FROM vouchers WHERE created_date = ?`,
        [today],
        function(voucherErr) {
          if (voucherErr) {
            console.error('Error clearing vouchers:', voucherErr);
            // Not fatal - continue
          }
          res.json({ success: true, cleared: this.changes || 0 });
        }
      );
    }
  );
});

// ========== CLASSES MANAGEMENT ==========

// Create class (admin)
app.post('/api/classes', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Тільки адміністратор' });
  const { name, teacher_id } = req.body || {};
  if (!name || typeof name !== 'string') return res.status(400).json({ error: 'Потрібна назва класу' });
  
  // If teacher_id provided, verify they exist and have role='teacher'
  if (teacher_id) {
    db.get('SELECT id, role FROM users WHERE id = ?', [teacher_id], (err, row) => {
      if (err || !row || row.role !== 'teacher') {
        return res.status(400).json({ error: 'Учитель не знайдений або невалідна роль' });
      }
      // Proceed with class creation
      const id = uuidv4();
      db.run('INSERT INTO classes (id, name, teacher_id) VALUES (?, ?, ?)', [id, name.trim(), teacher_id], (err) => {
        if (err) return res.status(500).json({ error: 'Помилка створення класу' });
        res.json({ success: true, id, name, teacher_id });
      });
    });
  } else {
    // No teacher assigned yet
    const id = uuidv4();
    db.run('INSERT INTO classes (id, name, teacher_id) VALUES (?, ?, ?)', [id, name.trim(), null], (err) => {
      if (err) return res.status(500).json({ error: 'Помилка створення класу' });
      res.json({ success: true, id, name, teacher_id: null });
    });
  }
});

// List classes (admin)
app.get('/api/classes', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Тільки адміністратор' });
  const q = `SELECT c.id, c.name, c.teacher_id, u.username as teacher_username, u.name as teacher_name, 
    (SELECT COUNT(*) FROM users s WHERE s.class_id = c.id AND s.role = 'student') as student_count
    FROM classes c LEFT JOIN users u ON u.id = c.teacher_id`;
  db.all(q, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Помилка отримання класів' });
    res.json(rows || []);
  });
});

// Public classes list (for registration/class dropdown) - intentionally public
app.get('/api/classes/public', (req, res) => {
  db.all('SELECT id, name FROM classes ORDER BY name', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Помилка отримання класів' });
    res.json(rows || []);
  });
});

// Get class details (admin or teacher of that class)
app.get('/api/classes/:id', authenticateToken, (req, res) => {
  const id = req.params.id;
  const kyivTime = new Date(new Date().toLocaleString('en-US', { timeZone: 'Europe/Kyiv' }));
  const today = kyivTime.toISOString().split('T')[0];
  
  db.get('SELECT * FROM classes WHERE id = ?', [id], (err, cls) => {
    if (err || !cls) return res.status(404).json({ error: 'Клас не знайдений' });
    if (req.user.role === 'teacher') {
      // ensure teacher is owner of this class (teacher_id matches)
      if (cls.teacher_id !== req.user.id) {
        return res.status(403).json({ error: 'Доступ заборонено' });
      }
      // fetch students in this class with their attendance status for today
      db.all(
        `SELECT u.id, u.username, u.name, 
                COALESCE(a.status, 'absent') as present
         FROM users u
         LEFT JOIN attendance a ON u.id = a.student_id AND a.attendance_date = ?
         WHERE u.role = "student" AND u.class_id = ?
         ORDER BY u.name`,
        [today, id],
        (err2, students) => {
          if (err2) return res.status(500).json({ error: 'Помилка отримання учнів' });
          res.json({ class: cls, students });
        }
      );
      return;
    }
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Доступ заборонено' });
    // Admin: get all students in class with their attendance status for today
    db.all(
      `SELECT u.id, u.username, u.name,
              COALESCE(a.status, 'absent') as present
       FROM users u
       LEFT JOIN attendance a ON u.id = a.student_id AND a.attendance_date = ?
       WHERE u.role = "student" AND u.class_id = ?
       ORDER BY u.name`,
      [today, id],
      (err2, students) => {
        if (err2) return res.status(500).json({ error: 'Помилка отримання учнів' });
        res.json({ class: cls, students });
      }
    );
  });
});

// Admin: update class assign teacher
app.put('/api/classes/:id/teacher', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Тільки адміністратор' });
  const classId = req.params.id;
  const { teacher_id } = req.body || {};
  
  // Verify class exists
  db.get('SELECT id FROM classes WHERE id = ?', [classId], (err, classRow) => {
    if (err || !classRow) {
      return res.status(404).json({ error: 'Клас не знайдений' });
    }
    
    // If teacher_id provided, verify teacher exists
    if (teacher_id) {
      db.get('SELECT id, role FROM users WHERE id = ?', [teacher_id], (e, teacherRow) => {
        if (e || !teacherRow || teacherRow.role !== 'teacher') {
          return res.status(400).json({ error: 'Учитель не знайдений' });
        }
        // Update class with new teacher
        db.run('UPDATE classes SET teacher_id = ? WHERE id = ?', [teacher_id, classId], function(uErr) {
          if (uErr) return res.status(500).json({ error: 'Помилка оновлення класу' });
          res.json({ success: true, classId, teacher_id });
        });
      });
    } else {
      // Remove teacher from class
      db.run('UPDATE classes SET teacher_id = NULL WHERE id = ?', [classId], function(uErr) {
        if (uErr) return res.status(500).json({ error: 'Помилка оновлення класу' });
        res.json({ success: true, classId, teacher_id: null });
      });
    }
  });
});

// Admin: add student to class
app.post('/api/classes/:id/students', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Тільки адміністратор' });
  const classId = req.params.id;
  const { student_id } = req.body || {};
  
  if (!student_id) {
    return res.status(400).json({ error: 'Потрібен ID учня' });
  }
  
  // Verify class exists
  db.get('SELECT id FROM classes WHERE id = ?', [classId], (err, classRow) => {
    if (err || !classRow) {
      return res.status(404).json({ error: 'Клас не знайдений' });
    }
    
    // Verify student exists, has role='student', and is not assigned to another class
    db.get('SELECT id, role, class_id FROM users WHERE id = ?', [student_id], (e, studentRow) => {
      if (e || !studentRow || studentRow.role !== 'student') {
        return res.status(400).json({ error: 'Учень не знайдений' });
      }
      if (studentRow.class_id && studentRow.class_id !== classId) {
        return res.status(409).json({
          error: 'Учень вже закріплений за іншим класом. Спочатку видаліть його з поточного класу.'
        });
      }
      if (studentRow.class_id === classId) {
        return res.status(409).json({ error: 'Учень вже доданий до цього класу' });
      }
      
      // Assign student to class
      db.run('UPDATE users SET class_id = ? WHERE id = ?', [classId, student_id], function(uErr) {
        if (uErr) return res.status(500).json({ error: 'Помилка додавання учня' });
        res.json({ success: true, student_id, classId });
      });
    });
  });
});

// Admin: remove student from class
app.delete('/api/classes/:id/students/:student_id', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Тільки адміністратор' });
  const { classId, student_id } = { classId: req.params.id, student_id: req.params.student_id };
  
  // Remove student from class (only role=student)
  db.run('UPDATE users SET class_id = NULL WHERE id = ? AND class_id = ? AND role = ?', [student_id, classId, 'student'], function(err) {
    if (err) return res.status(500).json({ error: 'Помилка видалення учня' });
    if (this.changes === 0) {
      return res.status(404).json({ error: 'Учень не в цьому класі' });
    }
    res.json({ success: true, student_id, classId });
  });
});

// Admin: delete class
app.delete('/api/classes/:id', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Тільки адміністратор' });
  const classId = req.params.id;

  // First, remove only students from this class (set class_id to NULL)
  db.run("UPDATE users SET class_id = NULL WHERE class_id = ? AND role = 'student'", [classId], (err) => {
    if (err) return res.status(500).json({ error: 'Помилка при видаленні учнів з класу' });
    
    // Then delete the class itself
    db.run('DELETE FROM classes WHERE id = ?', [classId], function(deletErr) {
      if (deletErr) return res.status(500).json({ error: 'Помилка при видаленні класу' });
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Клас не знайдений' });
      }
      res.json({ success: true, message: 'Клас видалено' });
    });
  });
});

// Teacher: get my classes
app.get('/api/teacher/my-classes', authenticateToken, (req, res) => {
  if (req.user.role !== 'teacher') return res.status(403).json({ error: 'Тільки вчитель' });
  // Find all classes where teacher_id = req.user.id
  db.all('SELECT id, name, teacher_id, (SELECT COUNT(*) FROM users WHERE class_id = classes.id AND role = "student") as student_count FROM classes WHERE teacher_id = ?', [req.user.id], (err, classes) => {
    if (err) return res.status(500).json({ error: 'Помилка отримання класів' });
    res.json(classes || []);
  });
});

// Admin: assign class to a user (set class_id)
app.put('/api/users/:id/class', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Тільки адміністратор' });
  const userId = req.params.id;
  const { class_id } = req.body || {};
  // validate user exists
  db.get('SELECT id, role, class_id FROM users WHERE id = ?', [userId], (err, userRow) => {
    if (err || !userRow) return res.status(404).json({ error: 'Користувач не знайдений' });
    if (class_id) {
      db.get('SELECT id FROM classes WHERE id = ?', [class_id], (cErr, cRow) => {
        if (cErr || !cRow) return res.status(400).json({ error: 'Клас не знайдений' });
        if (userRow.role === 'student' && userRow.class_id && userRow.class_id !== class_id) {
          return res.status(409).json({
            error: 'Учень вже закріплений за іншим класом. Спочатку видаліть його з поточного класу.'
          });
        }
        if (userRow.role === 'student' && userRow.class_id === class_id) {
          return res.status(409).json({ error: 'Учень вже доданий до цього класу' });
        }
        db.run('UPDATE users SET class_id = ? WHERE id = ?', [class_id, userId], function(uErr) {
          if (uErr) return res.status(500).json({ error: 'Помилка оновлення користувача' });
          res.json({ success: true, updated: this.changes || 0 });
        });
      });
    } else {
      // clear class
      db.run('UPDATE users SET class_id = NULL WHERE id = ?', [userId], function(uErr) {
        if (uErr) return res.status(500).json({ error: 'Помилка оновлення користувача' });
        res.json({ success: true, updated: this.changes || 0 });
      });
    }
  });
});

// Teacher: get my students
app.get('/api/teachers/my-students', authenticateToken, (req, res) => {
  if (req.user.role !== 'teacher') return res.status(403).json({ error: 'Тільки вчитель' });
  
  const kyivTime = new Date(new Date().toLocaleString('en-US', { timeZone: 'Europe/Kyiv' }));
  const today = kyivTime.toISOString().split('T')[0];
  
  // Find class where teacher_id = req.user.id
  db.get('SELECT id FROM classes WHERE teacher_id = ?', [req.user.id], (err, classRow) => {
    if (err) return res.status(500).json({ error: 'Помилка отримання даних вчителя' });
    if (!classRow) return res.status(400).json({ error: "Вчитель не прив'язаний до класу" });
    
    const classId = classRow.id;
    // Get students with their attendance status for today in ONE query
    db.all(
      `SELECT u.id, u.username, u.name, a.status 
       FROM users u
       LEFT JOIN attendance a ON u.id = a.student_id AND a.attendance_date = ?
       WHERE u.role = 'student' AND u.class_id = ? 
       ORDER BY u.name ASC`,
      [today, classId],
      (e, students) => {
        if (e) {
          console.error(`[ATTENDANCE READ] Error fetching students:`, e);
          return res.status(500).json({ error: 'Помилка отримання учнів' });
        }
        console.log(`[ATTENDANCE READ] Date: ${today}, Class: ${classId}, Students returned: ${students?.length || 0}`);
        students?.forEach(s => {
          console.log(`  - ${s.name} (${s.id}): status=${s.status || 'NULL'}`);
        });
        const result = (students || []).map(s => ({
          id: s.id,
          username: s.username,
          name: s.name,
          status: s.status || 'absent'  // Default to absent if no record
        }));
        res.json(result);
      }
    );
  });
});

// Student: get own attendance records
app.get('/api/student/me/attendance', authenticateToken, (req, res) => {
  if (req.user.role !== 'student') return res.status(403).json({ error: 'Тільки учень' });
  db.all(`SELECT a.attendance_date as date, a.status, c.name as class 
    FROM attendance a
    LEFT JOIN classes c ON a.class_id = c.id
    WHERE a.student_id = ?
    ORDER BY a.attendance_date DESC`, [req.user.id], (err, records) => {
    if (err) return res.status(500).json({ error: 'Помилка отримання даних' });
    res.json({ records: records || [] });
  });
});

// Student: get attendance summary
app.get('/api/student/me/attendance-summary', authenticateToken, (req, res) => {
  if (req.user.role !== 'student') return res.status(403).json({ error: 'Тільки учень' });
  db.all('SELECT status FROM attendance WHERE student_id = ?', [req.user.id], (err, records) => {
    if (err) return res.status(500).json({ error: 'Помилка обчислення статистики' });
    
    const summary = {
      total_days: records.length,
      present: 0,
      absent: 0,
      percentage: 0
    };
    
    records.forEach(r => {
      if (r.status === 'present') summary.present++;
      else if (r.status === 'absent') summary.absent++;
    });
    
    if (summary.total_days > 0) {
      summary.percentage = (summary.present / summary.total_days) * 100;
    }
    
    res.json(summary);
  });
});

// ========== END ATTENDANCE ==========

// ========== SERVE REACT SPA BUILD FILES ==========
// Must be AFTER all API routes so API requests aren't caught by the catch-all
const buildPath = path.join(__dirname, '..', 'frontend', 'build');
const buildPathExists = fs.existsSync(buildPath);
if (buildPathExists) {
  console.log(`📁 Serving React build from: ${buildPath}`);
  // Serve static assets with long cache lifetime, but ensure index.html is not aggressively cached
  app.use(express.static(buildPath, {
    maxAge: '30d',
    etag: false,
    setHeaders: (res, filePath) => {
      if (filePath.endsWith('index.html')) {
        // For SPA entry, always revalidate to pick up new deployments
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
      } else if (filePath.endsWith('.html')) {
        res.setHeader('Cache-Control', 'no-cache');
      } else {
        // For static assets (css/js/images) allow long caching and immutability
        res.setHeader('Cache-Control', 'public, max-age=2592000, immutable');
      }
    }
  }));

  // Serve index.html for all non-API routes (SPA routing)
  app.get('*', (req, res) => {
    // Skip API routes - they should 404, not serve index.html
    if (!req.path.startsWith('/api')) {
      res.sendFile(path.join(buildPath, 'index.html'));
    }
  });
} else {
  console.warn(`⚠️  Build folder not found at ${buildPath}. React app will not be served.`);
}

// Global error handlers
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// ========== GLOBAL ERROR HANDLER ==========
// This middleware catches all errors from routes and middleware
app.use((err, req, res, next) => {
  if (!res.headersSent) {
    console.error('🔴 Unhandled error:', err);
    res.status(err.status || 500).json({
      error: err.message || 'Internal server error',
      ...(process.env.NODE_ENV === 'development' && { details: err.stack })
    });
  }
});

// ========== START SERVER ==========
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n✅ SERVER RUNNING: http://localhost:${PORT}`);
  console.log(`   Health check: http://localhost:${PORT}/api/health`);
  console.log(`   Readiness check: http://localhost:${PORT}/api/ready`);
  console.log(`   Login: POST http://localhost:${PORT}/api/auth/login\n`);
});

// Keep server alive and handle shutdown
server.keepAliveTimeout = SERVER_KEEP_ALIVE_TIMEOUT_MS;
server.headersTimeout = SERVER_HEADERS_TIMEOUT_MS;
server.requestTimeout = SERVER_REQUEST_TIMEOUT_MS;
server.maxConnections = SERVER_MAX_CONNECTIONS;

server.on('connection', (socket) => {
  socket.setTimeout(SERVER_SOCKET_TIMEOUT_MS);
  socket.on('timeout', () => {
    socket.destroy();
  });
});

server.on('error', (err) => {
  console.error('Server error:', err);
  process.exit(1);
});

// ========== AUTOMATIC VOUCHER DISTRIBUTION ==========
// Distribute vouchers automatically at 9:00 AM Kyiv time to all present students
function getKyivTime() {
  const now = new Date();
  const kyivTime = new Date(now.toLocaleString('en-US', { timeZone: 'Europe/Kyiv' }));
  return kyivTime;
}

function distributeVouchersIfTime() {
  const kyivTime = getKyivTime();
  const hours = kyivTime.getHours();
  const minutes = kyivTime.getMinutes();
  
  // Distribute at 9:15 AM Kyiv time (between 9:15 and 9:16)
  if (hours === 9 && minutes === 15) {
    console.log(`🎫 [${kyivTime.toLocaleString('uk-UA')}] Starting automatic voucher distribution...`);
    
    const today = kyivTime.toISOString().split('T')[0];
    // If Redis/queue is available, enqueue a background job to perform distribution
    if (redis && distributeQueue) {
      try {
        distributeQueue.add('daily-distribute', { today });
        console.log('📥 Enqueued voucher distribution job (distribute-vouchers)');
        return;
      } catch (e) {
        console.warn('⚠️ Failed to enqueue distribution job, falling back to inline distribution', e.message || e);
      }
    }
    
    // Get all students who were marked as present today
    db.all(
      `SELECT DISTINCT u.id, u.username, u.name FROM users u 
       INNER JOIN attendance a ON u.id = a.student_id 
       WHERE u.role = 'student' AND a.attendance_date = ? AND a.status = 'present'`,
      [today],
      async (err, students) => {
        if (err) {
          console.error('❌ Error fetching students for voucher distribution:', err);
          return;
        }
        
        if (!students || students.length === 0) {
          console.log('ℹ️  No students marked as present for voucher distribution');
          return;
        }
        
        let distributed = 0;
        console.log(`📋 Found ${students.length} students marked as present. Distributing vouchers...`);
        
        for (const student of students) {
          // Check if already has voucher today
          db.get(
            'SELECT id FROM vouchers WHERE user_id = ? AND created_date = ?',
            [student.id, today],
            async (checkErr, existingVoucher) => {
              if (checkErr) {
                console.error(`  ❌ Error checking voucher for ${student.name}:`, checkErr);
                return;
              }
              
              if (existingVoucher) {
                console.log(`  ℹ️  ${student.name} already has voucher today`);
                return;
            }
            
            // Create voucher (record issued_at so expiration works)
            const voucherId = uuidv4();
            const qrCode = uuidv4();
            const issuedAt = new Date().toISOString();
            
            try {
              await new Promise((resolve, reject) => {
                // expire at end of today (set expires_date to today so UI can show "до 24:00 сьогодні")
                db.run(
                  'INSERT INTO vouchers (id, qr_code, user_id, student_name, created_date, expires_date, issued_at, max_uses, current_uses, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                  [voucherId, qrCode, student.id, student.name || student.username, today, today, issuedAt, 1, 0, 'active'],
                  (insertErr) => {
                    if (insertErr) {
                      console.error(`  ❌ Error creating voucher for ${student.name}:`, insertErr);
                      reject(insertErr);
                    } else {
                      distributed++;
                      try { voucherCreatedCounter.inc(); } catch (e) {}
                      console.log(`  ✓ Voucher created for ${student.name} - issued_at: ${issuedAt}`);
                      resolve();
                    }
                  }
                );
              });
            } catch (e) {
              console.error(`  ❌ Failed to create voucher for ${student.name}`);
            }
          }
        );
      }
      
      // Log completion (note: may not see total immediately due to async operations)
      setTimeout(() => {
        console.log(`✅ Automatic voucher distribution completed at ${getKyivTime().toLocaleString('uk-UA')}`);
      }, 5000);
    });
  }
}

// Run voucher distribution check every minute
const voucherDistributionInterval = setInterval(() => {
  distributeVouchersIfTime();
}, 60000); // Check every minute

// Also check on startup if it's 9:15 AM
console.log(`⏰ Automatic voucher distribution scheduler started (checks at 9:15 AM Kyiv time)`);

let isShuttingDown = false;
function gracefulShutdown(signal) {
  if (isShuttingDown) return;
  isShuttingDown = true;

  console.log(`\n${signal} received. Shutting down gracefully...`);
  clearInterval(voucherDistributionInterval);
  try { eventLoopDelayMonitor.disable(); } catch (e) {}

  const forceExitTimer = setTimeout(() => {
    console.error('⚠️ Forced shutdown after timeout');
    process.exit(1);
  }, SHUTDOWN_TIMEOUT_MS);
  if (typeof forceExitTimer.unref === 'function') {
    forceExitTimer.unref();
  }

  const finishExit = (code = 0) => {
    clearTimeout(forceExitTimer);
    process.exit(code);
  };

  server.close(() => {
    db.close((err) => {
      if (err) console.error('DB close error:', err);
      if (redis) {
        redis.quit().catch(() => {}).finally(() => finishExit(0));
        return;
      }
      finishExit(0);
    });
  });
}

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

// Export Redis instance for db-cache
module.exports = { redis, db };


