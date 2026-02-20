#!/usr/bin/env node
require('dotenv').config();

const fs = require('fs');
const path = require('path');
const { db, initDb, engine } = require('../db-wrapper');

const TABLE_CANDIDATES = [
  'users',
  'classes',
  'attendance',
  'vouchers',
  'voucher_usage',
  'audit_logs',
  'refresh_tokens',
  'config',
  'admin_config'
];

function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows || []);
    });
  });
}

function dbClose() {
  return new Promise((resolve) => {
    db.close(() => resolve());
  });
}

function safeTimestamp() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function copyIfExists(fromPath, toPath) {
  if (!fs.existsSync(fromPath)) return false;
  fs.copyFileSync(fromPath, toPath);
  return true;
}

async function exportDataJson(targetDir) {
  const payload = {
    meta: {
      createdAt: new Date().toISOString(),
      engine: engine(),
      nodeEnv: process.env.NODE_ENV || 'development',
      project: 'school-vouchers',
      formatVersion: 1
    },
    tables: {}
  };

  for (const tableName of TABLE_CANDIDATES) {
    try {
      const rows = await dbAll(`SELECT * FROM ${tableName}`);
      payload.tables[tableName] = rows;
    } catch (err) {
      // Table may not exist for this environment - skip.
    }
  }

  const jsonPath = path.join(targetDir, `backup-${safeTimestamp()}.json`);
  fs.writeFileSync(jsonPath, JSON.stringify(payload, null, 2), 'utf8');
  return jsonPath;
}

function backupSqliteFiles(targetDir) {
  const dbDir = path.resolve(__dirname, '..');
  const mainDb = path.join(dbDir, 'vouchers.db');
  const walDb = path.join(dbDir, 'vouchers.db-wal');
  const shmDb = path.join(dbDir, 'vouchers.db-shm');

  const copied = [];
  if (copyIfExists(mainDb, path.join(targetDir, `vouchers-${safeTimestamp()}.db`))) copied.push('db');
  if (copyIfExists(walDb, path.join(targetDir, `vouchers-${safeTimestamp()}.db-wal`))) copied.push('wal');
  if (copyIfExists(shmDb, path.join(targetDir, `vouchers-${safeTimestamp()}.db-shm`))) copied.push('shm');
  return copied;
}

async function main() {
  await initDb();
  const backupDir = path.resolve(__dirname, '..', 'backups');
  ensureDir(backupDir);

  const jsonPath = await exportDataJson(backupDir);
  const dbEngine = engine();

  let copiedSqliteArtifacts = [];
  if (dbEngine === 'sqlite') {
    copiedSqliteArtifacts = backupSqliteFiles(backupDir);
  }

  await dbClose();

  console.log(`Backup completed: ${jsonPath}`);
  if (copiedSqliteArtifacts.length > 0) {
    console.log(`SQLite artifacts copied: ${copiedSqliteArtifacts.join(', ')}`);
  }
}

main().catch(async (err) => {
  console.error('Backup failed:', err.message || err);
  try { await dbClose(); } catch (_) {}
  process.exit(1);
});
