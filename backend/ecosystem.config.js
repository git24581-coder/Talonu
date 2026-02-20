const defaultInstances = process.platform === 'win32' ? 2 : 'max';

module.exports = {
  apps: [
    {
      name: 'school-vouchers-backend',
      script: 'server.js',
      cwd: __dirname,
      exec_mode: 'cluster',
      instances: process.env.PM2_INSTANCES || defaultInstances,
      autorestart: true,
      watch: false,
      max_memory_restart: process.env.PM2_MAX_MEMORY_RESTART || '512M',
      kill_timeout: 10000,
      listen_timeout: 10000,
      env: {
        NODE_ENV: 'development'
      },
      env_production: {
        NODE_ENV: 'production'
      }
    }
  ]
};
