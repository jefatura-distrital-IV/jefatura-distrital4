// Sistema de backups automatizados para SQLite
const fs = require('fs');
const path = require('path');

const BACKUP_PATH = process.env.BACKUP_PATH || './backups';
const DB_PATH = './database.sqlite';

// Asegurar que el directorio de backups existe
if (!fs.existsSync(BACKUP_PATH)) {
  fs.mkdirSync(BACKUP_PATH, { recursive: true });
}

/**
 * Crear un backup de la base de datos SQLite
 * @returns {Promise<string>} Ruta del archivo de backup creado
 */
async function createBackup() {
  return new Promise((resolve, reject) => {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupFileName = `database-backup-${timestamp}.sqlite`;
    const backupPath = path.join(BACKUP_PATH, backupFileName);

    // Verificar que el archivo de BD existe
    if (!fs.existsSync(DB_PATH)) {
      return reject(new Error(`Base de datos no encontrada: ${DB_PATH}`));
    }

    // Copiar el archivo
    fs.copyFile(DB_PATH, backupPath, (err) => {
      if (err) {
        return reject(err);
      }
      console.log(`Backup creado: ${backupPath}`);
      resolve(backupPath);
    });
  });
}

/**
 * Limpiar backups antiguos (mantener solo los últimos N días)
 * @param {number} daysToKeep - Número de días de backups a mantener
 */
function cleanOldBackups(daysToKeep = 30) {
  const files = fs.readdirSync(BACKUP_PATH);
  const now = Date.now();
  const daysInMs = daysToKeep * 24 * 60 * 60 * 1000;

  files.forEach((file) => {
    if (file.startsWith('database-backup-') && file.endsWith('.sqlite')) {
      const filePath = path.join(BACKUP_PATH, file);
      const stats = fs.statSync(filePath);
      const fileAge = now - stats.mtimeMs;

      if (fileAge > daysInMs) {
        fs.unlinkSync(filePath);
        console.log(`Backup antiguo eliminado: ${file}`);
      }
    }
  });
}

/**
 * Programar backups automáticos
 * @param {string} frequency - Frecuencia: 'daily', 'hourly', 'weekly'
 */
function scheduleBackups(frequency = 'daily') {
  const frequencies = {
    daily: 24 * 60 * 60 * 1000,      // 24 horas
    hourly: 60 * 60 * 1000,           // 1 hora
    weekly: 7 * 24 * 60 * 60 * 1000, // 7 días
  };

  const interval = frequencies[frequency] || frequencies.daily;

  // Crear backup inicial
  createBackup().catch(console.error);

  // Programar backups periódicos
  setInterval(() => {
    createBackup()
      .then(() => cleanOldBackups())
      .catch(console.error);
  }, interval);

  console.log(`Backups programados cada: ${frequency}`);
}

module.exports = {
  createBackup,
  cleanOldBackups,
  scheduleBackups,
};

