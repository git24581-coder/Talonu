/**
 * Database wrapper - allows server.js to work with BOTH SQLite and PostgreSQL
 * Automatically detects DATABASE_URL and switches engines
 */

const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const { Pool } = require('pg');

let engine = null;  // 'sqlite' or 'postgres'
let sqliteDb = null;
let pgPool = null;

// SQLite queries in this project use "?" placeholders.
// PostgreSQL requires "$1, $2, ..." placeholders.
function toPostgresParamsSql(sql) {
  if (typeof sql !== 'string' || sql.indexOf('?') === -1) return sql;

  let index = 0;
  let inSingleQuote = false;
  let converted = '';

  for (let i = 0; i < sql.length; i++) {
    const ch = sql[i];

    if (ch === "'") {
      // Handle escaped single quote in SQL literal: ''
      if (inSingleQuote && sql[i + 1] === "'") {
        converted += "''";
        i++;
        continue;
      }
      inSingleQuote = !inSingleQuote;
      converted += ch;
      continue;
    }

    if (!inSingleQuote && ch === '?') {
      index += 1;
      converted += `$${index}`;
      continue;
    }

    converted += ch;
  }

  return converted;
}

// Initialize database based on environment
async function initDb() {
  const dbUrl = process.env.DATABASE_URL;
  
  if (dbUrl && dbUrl.startsWith('postgres')) {
    console.log('🐘 Using PostgreSQL...');
    engine = 'postgres';
    
    pgPool = new Pool({
      connectionString: dbUrl,
      max: 20,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 2000,
    });

    pgPool.on('error', (err) => {
      console.error('❌ PostgreSQL Error:', err);
    });

    try {
      await pgPool.query('SELECT NOW()');
      console.log('✓ Connected to PostgreSQL');
      
      // Create tables/indexes
      await setupPostgresSchema();
      return pgPool;
    } catch (e) {
      console.error('❌ PostgreSQL connect failed:', e.message);
      throw e;
    }
  } else {
    // SQLite (default)
    console.log('📁 Using SQLite...');
    engine = 'sqlite';
    
    return new Promise((resolve, reject) => {
      const dbPath = path.join(__dirname, 'vouchers.db');
      sqliteDb = new sqlite3.Database(dbPath, (err) => {
        if (err) {
          console.error('❌ SQLite Error:', err);
          reject(err);
        } else {
          console.log('✓ Connected to SQLite');
          
          // Enable aggressive performance settings for high concurrency
          sqliteDb.serialize(() => {
            sqliteDb.run('PRAGMA journal_mode=WAL');        // Write-ahead logging for concurrent reads
            sqliteDb.run('PRAGMA synchronous=NORMAL');      // Balance safety & speed
            sqliteDb.run('PRAGMA cache_size=50000');        // 50MB cache
            sqliteDb.run('PRAGMA temp_store=MEMORY');       // Temp tables in RAM
            sqliteDb.run('PRAGMA query_only=OFF');          // Allow writes
            sqliteDb.run('PRAGMA busy_timeout=5000');       // 5s timeout before SQLITE_BUSY
            sqliteDb.run('PRAGMA wal_autocheckpoint=1000'); // Checkpoint every 1000 pages
            sqliteDb.run('PRAGMA mmap_size=30000000');      // Memory-map file
          });
          
          resolve(null);  // SQLite wrapped by singleton
        }
      });
    });
  }
}

async function setupPostgresSchema() {
  const schemas = [
    `CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      email TEXT,
      role TEXT DEFAULT 'student',
      name TEXT,
      class_id TEXT,
      failed_attempts INTEGER DEFAULT 0,
      locked_until TIMESTAMP,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );`,
    
    `CREATE TABLE IF NOT EXISTS vouchers (
      id TEXT PRIMARY KEY,
      qr_code TEXT UNIQUE NOT NULL,
      user_id TEXT NOT NULL,
      student_name TEXT NOT NULL,
      created_date DATE,
      expires_date DATE,
      issued_at TIMESTAMP,
      max_uses INTEGER DEFAULT 1,
      current_uses INTEGER DEFAULT 0,
      status TEXT DEFAULT 'active',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id),
      UNIQUE(user_id, created_date)
    );`,
    
    `CREATE TABLE IF NOT EXISTS voucher_usage (
      id TEXT PRIMARY KEY,
      voucher_id TEXT NOT NULL,
      used_date DATE NOT NULL,
      used_time TIME NOT NULL,
      cashier_id TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (voucher_id) REFERENCES vouchers(id),
      FOREIGN KEY (cashier_id) REFERENCES users(id)
    );`,
    
    `CREATE TABLE IF NOT EXISTS classes (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      teacher_id TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (teacher_id) REFERENCES users(id)
    );`,
    
    `CREATE TABLE IF NOT EXISTS attendance (
      id TEXT PRIMARY KEY,
      student_id TEXT NOT NULL,
      class_id TEXT,
      attendance_date DATE NOT NULL,
      lesson_number INTEGER DEFAULT 1,
      status TEXT DEFAULT 'present',
      comment TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (student_id) REFERENCES users(id),
      FOREIGN KEY (class_id) REFERENCES classes(id)
    );`,
    
    `CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      action TEXT NOT NULL,
      ip TEXT,
      user_agent TEXT,
      details TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );`,
    
    `CREATE TABLE IF NOT EXISTS refresh_tokens (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      token TEXT NOT NULL,
      expires_at TIMESTAMP NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );`,
    
    // Indexes
    `CREATE INDEX IF NOT EXISTS idx_vouchers_user_id ON vouchers(user_id);`,
    `CREATE INDEX IF NOT EXISTS idx_vouchers_created_date ON vouchers(created_date);`,
    `CREATE INDEX IF NOT EXISTS idx_vouchers_status ON vouchers(status);`,
    `CREATE INDEX IF NOT EXISTS idx_vouchers_qr_code ON vouchers(qr_code);`,
    `CREATE INDEX IF NOT EXISTS idx_voucher_usage_voucher_id ON voucher_usage(voucher_id);`,
    `CREATE INDEX IF NOT EXISTS idx_attendance_student_id ON attendance(student_id);`,
    `CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);`,
  ];

  for (const sql of schemas) {
    try {
      await pgPool.query(sql);
    } catch (e) {
      // Ignore "already exists" errors
      if (!e.message.includes('already exists')) {
        console.warn('⚠️ Schema setup:', e.message);
      }
    }
  }
  console.log('✓ PostgreSQL schemas ready');
}

// Wrapper functions that work for BOTH SQLite and PostgreSQL
const db = {
  // Serialize - SQLite specific, no-op for PostgreSQL
  serialize(callback) {
    if (engine === 'sqlite') {
      sqliteDb.serialize(callback);
    } else {
      callback();
    }
  },

  // Run query
  run(sql, params, callback) {
    if (!callback && typeof params === 'function') {
      callback = params;
      params = [];
    }
    
    // Defensive check for callback
    if (typeof callback !== 'function') {
      callback = () => {}; // No-op fallback
    }

    if (engine === 'sqlite') {
      sqliteDb.run(sql, params, function(err) {
        callback(err, { lastID: this.lastID, changes: this.changes });
      });
    } else {
      const pgSql = toPostgresParamsSql(sql);
      pgPool.query(pgSql, params, (err, res) => {
        callback(err, { lastID: null, changes: res?.rowCount || 0, rows: res?.rows || [] });
      });
    }
  },

  // Get single row
  get(sql, params, callback) {
    if (!callback && typeof params === 'function') {
      callback = params;
      params = [];
    }
    
    // Defensive check for callback
    if (typeof callback !== 'function') {
      callback = () => {}; // No-op fallback
    }

    if (engine === 'sqlite') {
      sqliteDb.get(sql, params, callback);
    } else {
      const pgSql = toPostgresParamsSql(sql);
      pgPool.query(pgSql, params, (err, res) => {
        callback(err, res?.rows?.[0]);
      });
    }
  },

  // Get all rows
  all(sql, params, callback) {
    if (!callback && typeof params === 'function') {
      callback = params;
      params = [];
    }
    
    // Defensive check for callback
    if (typeof callback !== 'function') {
      callback = () => {}; // No-op fallback
    }

    if (engine === 'sqlite') {
      sqliteDb.all(sql, params, callback);
    } else {
      const pgSql = toPostgresParamsSql(sql);
      pgPool.query(pgSql, params, (err, res) => {
        callback(err, res?.rows || []);
      });
    }
  },

  // Close connection
  close(callback) {
    if (engine === 'sqlite') {
      sqliteDb.close(callback);
    } else {
      pgPool.end(callback);
    }
  },

  // Error handler
  on(event, handler) {
    if (engine === 'sqlite') {
      sqliteDb.on(event, handler);
    } else if (event === 'error') {
      pgPool.on('error', handler);
    }
  }
};

module.exports = { db, initDb, engine: () => engine };
