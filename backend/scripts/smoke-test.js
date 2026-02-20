#!/usr/bin/env node
require('dotenv').config();

const axios = require('axios');

const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.SMOKE_BASE_URL || `http://localhost:${PORT}`;
const ADMIN_USERNAME = process.env.SMOKE_ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.SMOKE_ADMIN_PASSWORD || 'admin123';

function logStep(step, ok, details = '') {
  const mark = ok ? 'OK' : 'FAIL';
  console.log(`[${mark}] ${step}${details ? ` -> ${details}` : ''}`);
}

async function main() {
  const api = axios.create({
    baseURL: BASE_URL,
    timeout: 12000,
    validateStatus: () => true,
    withCredentials: true
  });

  console.log(`Smoke test started for ${BASE_URL}`);

  const health = await api.get('/api/health');
  const healthOk = health.status === 200;
  logStep('GET /api/health', healthOk, `status=${health.status}`);
  if (!healthOk) process.exit(1);

  const login = await api.post('/api/auth/login', {
    username: ADMIN_USERNAME,
    password: ADMIN_PASSWORD
  });
  const loginOk = login.status === 200 && login.data && login.data.token;
  logStep('POST /api/auth/login', loginOk, `status=${login.status}`);
  if (!loginOk) process.exit(1);

  const token = login.data.token;
  const authApi = axios.create({
    baseURL: BASE_URL,
    timeout: 12000,
    validateStatus: () => true,
    headers: { Authorization: `Bearer ${token}` },
    withCredentials: true
  });

  const users = await authApi.get('/api/users');
  const usersOk = users.status === 200 && Array.isArray(users.data);
  logStep('GET /api/users', usersOk, `status=${users.status}, count=${Array.isArray(users.data) ? users.data.length : 0}`);
  if (!usersOk) process.exit(1);

  const classesPublic = await api.get('/api/classes/public');
  const classesOk = classesPublic.status === 200 && Array.isArray(classesPublic.data);
  logStep('GET /api/classes/public', classesOk, `status=${classesPublic.status}, count=${Array.isArray(classesPublic.data) ? classesPublic.data.length : 0}`);
  if (!classesOk) process.exit(1);

  const students = users.data.filter((u) => u.role === 'student');
  if (students.length > 0) {
    const target = students[0];
    const setAttendance = await authApi.post('/api/users/attendance/set', { userIds: [target.id] });
    const setOk = setAttendance.status === 200 && setAttendance.data && setAttendance.data.success === true;
    logStep('POST /api/users/attendance/set', setOk, `status=${setAttendance.status}, student=${target.id}`);
    if (!setOk) process.exit(1);

    const vouchers = await authApi.get(`/api/vouchers/user/${target.id}`);
    const vouchersOk = vouchers.status === 200 && Array.isArray(vouchers.data);
    logStep('GET /api/vouchers/user/:id', vouchersOk, `status=${vouchers.status}, count=${Array.isArray(vouchers.data) ? vouchers.data.length : 0}`);
    if (!vouchersOk) process.exit(1);
  } else {
    logStep('Student-dependent checks', true, 'no students found, skipped');
  }

  console.log('Smoke test finished successfully.');
}

main().catch((err) => {
  console.error('Smoke test failed:', err.message || err);
  process.exit(1);
});
