module.exports = {
  apps: [
    {
      name: "revdata-web",
      script: "server.js",
      cwd: "/home/wwalld/subdominios/revdata.alldaex.co",
      exec_mode: "fork",
      instances: 1,
      watch: false,
      max_memory_restart: "300M",
      env: { NODE_ENV: "production", PORT: 3020 }
    },
    {
      name: "revdata-jobs",
      script: "index.js",
      cwd: "/home/wwalld/subdominios/revdata.alldaex.co",
      exec_mode: "fork",
      instances: 1,
      watch: false,                 // evita reinicios por cambios de archivos
      autorestart: true,            // PM2 lo reinicia si muere
      min_uptime: "10s",            // si cae antes de 10s se considera “inestable”
      exp_backoff_restart_delay: 1000, // 1s, luego 2s, 4s... evita loops agresivos
      restart_delay: 2000,          // pausa entre reinicios normales
      max_memory_restart: "300M",   // reinicia si se pasa de memoria
      env: { NODE_ENV: "production" }
    }
  ]
}
