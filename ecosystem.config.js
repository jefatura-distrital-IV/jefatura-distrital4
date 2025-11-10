module.exports = {
  apps: [
    {
      name: 'distrital4-jefatura',
      script: 'server.js',
      instances: 1, // puedes subir a 'max' para cluster
      exec_mode: 'fork', // o 'cluster'
      env: {
        NODE_ENV: 'development',
        PORT: 3001,
        JWT_SECRET: 'supersecretkey'
      },
      env_production: {
        NODE_ENV: 'production',
        PORT: 3001,
        // Cambia este valor en el servidor a un secreto real mediante variables de entorno o pm2
        JWT_SECRET: 'cambia-esto-en-produccion'
      }
    }
  ]
};


