#!/usr/bin/env node
require('dotenv').config();

const IORedis = require('ioredis');
const { Worker } = require('bullmq');
const { v4: uuidv4 } = require('uuid');
const { db, initDb, engine } = require('../db-wrapper');

const REDIS_URL = process.env.REDIS_URL;

function getKyivDateIso() {
  const kyivTime = new Date(new Date().toLocaleString('en-US', { timeZone: 'Europe/Kyiv' }));
  return kyivTime.toISOString().split('T')[0];
}

function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row || null);
    });
  });
}

function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows || []);
    });
  });
}

function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, (err, result) => {
      if (err) return reject(err);
      resolve(result || { changes: 0 });
    });
  });
}

async function distributeForDate(today) {
  const students = await dbAll(
    `SELECT DISTINCT u.id, u.username, u.name
     FROM users u
     INNER JOIN attendance a ON u.id = a.student_id
     WHERE u.role = 'student' AND a.attendance_date = ? AND a.status = 'present'`,
    [today]
  );

  if (students.length === 0) {
    return { created: 0, skipped: 0, scannedStudents: 0 };
  }

  let created = 0;
  let skipped = 0;

  for (const student of students) {
    const existing = await dbGet(
      'SELECT id FROM vouchers WHERE user_id = ? AND created_date = ?',
      [student.id, today]
    );

    if (existing) {
      skipped += 1;
      continue;
    }

    const voucherId = uuidv4();
    const qrCode = uuidv4();
    const issuedAt = new Date().toISOString();

    await dbRun(
      'INSERT INTO vouchers (id, qr_code, user_id, student_name, created_date, expires_date, issued_at, max_uses, current_uses, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [voucherId, qrCode, student.id, student.name || student.username, today, today, issuedAt, 1, 0, 'active']
    );
    created += 1;
  }

  return { created, skipped, scannedStudents: students.length };
}

async function runOneShotWithoutQueue() {
  const today = getKyivDateIso();
  const result = await distributeForDate(today);
  console.log(`[worker] done (one-shot): ${JSON.stringify(result)}`);
}

async function start() {
  await initDb();
  console.log(`[worker] db initialized (${engine()})`);

  if (!REDIS_URL) {
    console.log('[worker] REDIS_URL is not set. Running one-shot distribution and exiting.');
    await runOneShotWithoutQueue();
    db.close(() => process.exit(0));
    return;
  }

  const redis = new IORedis(REDIS_URL, {
    maxRetriesPerRequest: null,
    enableReadyCheck: true
  });

  const worker = new Worker(
    'distribute-vouchers',
    async (job) => {
      const today = String(job?.data?.today || getKyivDateIso());
      const result = await distributeForDate(today);
      console.log(`[worker] job ${job.id} done: ${JSON.stringify(result)}`);
      return result;
    },
    {
      connection: redis,
      concurrency: 2
    }
  );

  worker.on('ready', () => {
    console.log('[worker] distribute-vouchers worker is ready');
  });

  worker.on('failed', (job, err) => {
    console.error(`[worker] job ${job?.id || 'unknown'} failed:`, err.message || err);
  });

  worker.on('error', (err) => {
    console.error('[worker] fatal worker error:', err.message || err);
  });

  const shutdown = async (signal) => {
    console.log(`[worker] ${signal} received, shutting down...`);
    try { await worker.close(); } catch (_) {}
    try { await redis.quit(); } catch (_) {}
    db.close(() => process.exit(0));
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

start().catch((err) => {
  console.error('[worker] startup failed:', err.message || err);
  db.close(() => process.exit(1));
});
