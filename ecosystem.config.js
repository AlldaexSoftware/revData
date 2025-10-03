// ecosystem.config.js
const path = require('path');
const CWD = __dirname; // ruta de la carpeta donde está este archivo

module.exports = {
  apps: [
    {
      name: 'revdata-web',
      script: 'server.js',
      cwd: CWD,
      exec_mode: 'fork',
      instances: 1,
      watch: false,
      max_memory_restart: '300M',
      env: {
        NODE_ENV: 'production',
        PORT: 3020 // backend local para proxy inverso
      }
    },
    {
      name: 'revdata-jobs',
      script: 'index.js',
      cwd: CWD,
      exec_mode: 'fork',
      instances: 1,
      watch: false,
      autorestart: true,
      min_uptime: '10s',
      exp_backoff_restart_delay: 1000,
      restart_delay: 2000,
      max_memory_restart: '300M',
      env: {
        NODE_ENV: 'production'
      }
    }
  ]
};
