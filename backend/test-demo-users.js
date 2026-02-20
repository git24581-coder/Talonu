#!/usr/bin/env node
/**
 * Test script to verify demo users are created and can be viewed by admin
 */
require('dotenv').config();
const http = require('http');

const BASE_URL = 'http://localhost:3000';

function makeRequest(method, path, body = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(BASE_URL + path);
    const options = {
      method,
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      headers: {
        'Content-Type': 'application/json'
      }
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(data || '{}') });
        } catch (e) {
          resolve({ status: res.statusCode, body: data });
        }
      });
    });

    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

async function testDemo() {
  console.log('🧪 Testing demo users creation and admin view...\n');

  try {
    // 1. Test health endpoint
    console.log('1️⃣  Testing health endpoint...');
    const health = await makeRequest('GET', '/api/health');
    console.log(`   Status: ${health.status} ${health.status === 200 ? '✓' : '✗'}`);

    // 2. Login as admin
    console.log('\n2️⃣  Testing admin login...');
    const loginRes = await makeRequest('POST', '/api/auth/login', {
      username: 'admin',
      password: 'admin123'
    });
    console.log(`   Status: ${loginRes.status} ${loginRes.status === 200 ? '✓' : '✗'}`);
    if (loginRes.status === 200) {
      console.log(`   Token: ${loginRes.body.token ? 'OK' : 'MISSING'}`);
      console.log(`   User: ${loginRes.body.user.username} (role: ${loginRes.body.user.role})`);
    }

    const adminToken = loginRes.body.token;
    if (!adminToken) {
      console.error('   ❌ Could not get admin token');
      return;
    }

    // 3. Get students list
    console.log('\n3️⃣  Getting students list (for admin)...');
    const studentsRes = await makeRequest('GET', '/api/users/attendance', null);
    studentsRes.options = {
      headers: { Authorization: `Bearer ${adminToken}` }
    };
    console.log(`   Status: ${studentsRes.status}`);
    console.log(`   Students found: ${studentsRes.body?.length || 0}`);
    if (studentsRes.body && Array.isArray(studentsRes.body)) {
      studentsRes.body.forEach((s, i) => {
        console.log(`     ${i + 1}. ${s.name || '?'} (${s.status || 'absent'})`);
      });
    }

    // 4. Get statistics
    console.log('\n4️⃣  Getting admin statistics...');
    const statsRes = await makeRequest('GET', '/api/stats', null);
    statsRes.options = {
      headers: { Authorization: `Bearer ${adminToken}` }
    };
    console.log(`   Status: ${statsRes.status}`);
    console.log(`   Students in stats: ${statsRes.body?.length || 0}`);

    console.log('\n✅ Test complete!');
  } catch (err) {
    console.error('❌ Error:', err.message);
  }
}

// Wait for server to start then run tests
setTimeout(testDemo, 2000);
