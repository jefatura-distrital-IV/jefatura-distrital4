// Sistema de logging estructurado
// Reemplaza los console.log por un sistema de logging más robusto

const logLevels = {
  ERROR: 0,
  WARN: 1,
  INFO: 2,
  DEBUG: 3,
};

const logLevelNames = {
  0: 'ERROR',
  1: 'WARN',
  2: 'INFO',
  3: 'DEBUG',
};

// Determinar nivel de log según variable de entorno
const getLogLevel = () => {
  const envLevel = process.env.LOG_LEVEL || 'info';
  const levelMap = {
    error: logLevels.ERROR,
    warn: logLevels.WARN,
    info: logLevels.INFO,
    debug: logLevels.DEBUG,
  };
  return levelMap[envLevel.toLowerCase()] || logLevels.INFO;
};

const currentLogLevel = getLogLevel();

// Función de logging
const log = (level, message, data = {}) => {
  if (level > currentLogLevel) {
    return; // No loggear si el nivel es menor al configurado
  }

  const timestamp = new Date().toISOString();
  const logEntry = {
    timestamp,
    level: logLevelNames[level],
    message,
    ...data,
  };

  // En producción, usar JSON estructurado
  if (process.env.NODE_ENV === 'production') {
    console.log(JSON.stringify(logEntry));
  } else {
    // En desarrollo, usar formato más legible
    console.log(`[${timestamp}] [${logLevelNames[level]}] ${message}`, data && Object.keys(data).length > 0 ? data : '');
  }
};

// Funciones de logging por nivel
const logger = {
  error: (message, data) => log(logLevels.ERROR, message, data),
  warn: (message, data) => log(logLevels.WARN, message, data),
  info: (message, data) => log(logLevels.INFO, message, data),
  debug: (message, data) => log(logLevels.DEBUG, message, data),
};

module.exports = logger;

