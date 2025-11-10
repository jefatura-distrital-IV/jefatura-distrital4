// Cargar variables de entorno
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Sequelize, DataTypes } = require('sequelize');

// Importar módulos de mejoras
const logger = require('./utils/logger');
const { errorHandler, notFoundHandler, validationErrorHandler } = require('./middleware/errorHandler');
const { validateUserData } = require('./validators/userValidator');
const { scheduleBackups } = require('./utils/backup');

const app = express();
app.disable('x-powered-by');

// Middleware de logging de peticiones
app.use((req, res, next) => {
  logger.debug(`Petición recibida: ${req.method} ${req.originalUrl}`, {
    ip: req.ip,
    userAgent: req.get('user-agent')
  });
  next();
});

const PORT = process.env.PORT || 3001;

// ... código existente arriba ...

// Configuración de Sequelize para diferentes bases de datos
let sequelize;

if (process.env.DATABASE_URL) {
  // Usar DATABASE_URL si está disponible (preferido para despliegues como Render)
  sequelize = new Sequelize(process.env.DATABASE_URL, {
    dialect: 'postgres',
    logging: false,
    dialectOptions: {
      ssl: {
        require: true,
        rejectUnauthorized: false // Necesario para la conexión SSL en Render
      }
    }
  });
  logger.info('Configuración de base de datos: PostgreSQL (usando DATABASE_URL)');
} else if (process.env.DB_DIALECT === 'postgres') {
  sequelize = new Sequelize(process.env.DB_NAME, process.env.DB_USER, process.env.DB_PASSWORD, {
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    dialect: 'postgres',
    logging: false,
    dialectOptions: {
      ssl: process.env.DB_SSL === 'true' ? {
        require: true,
        rejectUnauthorized: false // Ajustar según el proveedor de hosting
      } : false
    }
  });
  logger.info('Configuración de base de datos: PostgreSQL');
} else if (process.env.DB_DIALECT === 'mysql') {
  sequelize = new Sequelize(process.env.DB_NAME, process.env.DB_USER, process.env.DB_PASSWORD, {
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    dialect: 'mysql',
    logging: false,
  });
  logger.info('Configuración de base de datos: MySQL');
} else { // Por defecto, usa SQLite
  sequelize = new Sequelize({
    dialect: 'sqlite',
    storage: './database.sqlite', // Archivo de la base de datos local
    logging: false,
  });
  logger.info('Configuración de base de datos: SQLite (por defecto)');
}

// Test de conexión a la base de datos
async function connectDB() {
  try {
    await sequelize.authenticate();
    // Mensaje de log genérico
    logger.info('Conexión a la base de datos establecida exitosamente');
  } catch (error) {
    // Mensaje de log genérico
    logger.error('No se pudo conectar a la base de datos', { error: error.message });
  }
}

// ... código existente abajo ...

connectDB();

// Middlewares
// CORS restringido por entorno (ALLOWED_ORIGINS como lista separada por comas)
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '*')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

app.use(cors({
  origin: (origin, callback) => {
    // En desarrollo, permitir cualquier origen
    if (process.env.NODE_ENV === 'development') {
      return callback(null, true);
    }
    
    // En producción, validar origen
    if (!origin || allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    logger.warn('Intento de acceso desde origen no permitido', { origin, allowedOrigins });
    return callback(new Error('Origin not allowed by CORS'));
  },
  credentials: true,
}));

// Configuración mejorada de Helmet
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));
// Seguridad adicional de contenido
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});
app.use(express.json());

// Bloquear acceso directo a archivos sensibles
app.use((req, res, next) => {
  const forbidden = [
    '/database.sqlite',
    '/database.sqlite-journal',
    '/backup-pre-edit-2025-10-14.zip'
  ];
  if (forbidden.includes(req.path) || /\.sqlite(\.|$)/i.test(req.path)) {
    return res.status(404).end();
  }
  next();
});

// Archivos estáticos solo desde la raíz actual, pero con bloqueo anterior
app.use(express.static(__dirname));

// Clave secreta para JWT
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '8h';

if (process.env.NODE_ENV === 'production' && JWT_SECRET === 'supersecretkey') {
  logger.error('Configuración insegura: define JWT_SECRET en producción');
  process.exit(1);
}

if (process.env.NODE_ENV === 'production' && JWT_SECRET.length < 32) {
  logger.warn('JWT_SECRET es muy corto. Se recomienda al menos 32 caracteres para producción');
}

// Definición del modelo User
const User = sequelize.define('User', {
  id: {
    type: DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  },
  name: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  lastName: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  phone: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  hierarchy: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  username: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  role: {
    type: DataTypes.STRING,
    allowNull: false,
    defaultValue: 'user',
  },
}, {
  // Opciones del modelo
  timestamps: false, // No queremos createdAt y updatedAt
});

// Definición del modelo Novedad
const Novedad = sequelize.define('Novedad', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
  },
  fechaDelHecho: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  horaDelHecho: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  calle: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  altura: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  entreCalles: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  barrio: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  coordenadas: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  encuadreLegal: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  victima: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  edadVictima: {
    type: DataTypes.STRING,
    allowNull: true
  },
  generoVictima: {
    type: DataTypes.STRING,
    allowNull: true
  },
  observaciones: {
    type: DataTypes.TEXT,
    allowNull: true,
  },
  sumario: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  expediente: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  dependencia: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  detallesNovedad: {
    type: DataTypes.TEXT,
    allowNull: true,
  },
  lugar: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  bienAfectado: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  nombreImputado: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  esclarecidos: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  fechaCreacion: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  horaCarga: {
    type: DataTypes.STRING,
    allowNull: true,
  },
}, {
  timestamps: false,
});

// Sincronizar modelos con la base de datos
async function syncDB() {
  try {
    const alter = process.env.DB_ALTER === 'true';
    await sequelize.sync({ alter });
    logger.info('Modelos sincronizados con la base de datos');
    
    // Asegurarse de que el usuario admin exista
    const adminUser = await User.findOne({ where: { username: 'admin' } });
    if (!adminUser) {
      const defaultPassword = process.env.ADMIN_DEFAULT_PASSWORD || 'hijoteamo2';
      const hashedPassword = await bcrypt.hash(defaultPassword, 10);
      await User.create({ username: 'admin', password: hashedPassword, role: 'admin' });
      logger.warn('Usuario admin creado con contraseña por defecto. CAMBIA LA CONTRASEÑA EN PRODUCCIÓN', {
        username: 'admin',
        password: defaultPassword
      });
    }

  } catch (error) {
    logger.error('Error al sincronizar modelos o crear admin', { error: error.message });
    throw error;
  }
}

// Middleware para autenticación JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401); // Si no hay token, acceso no autorizado

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // Token inválido o expirado
    req.user = user;
    next();
  });
}

const ALL_OFFICIAL_ROLES = [
  'admin',
  'user-oficiales',
  'OFICIAL DE 15',
  'OFICIAL DE 20',
  'OFICIAL DE 65',
  'OFICIAL DE 18',
  'OFICIAL MANZANO HISTORICO',
  'OFICIAL CORDON DEL PLATA',
  'JEF.DPTAL.TUNUYAN',
  'JEF.DPTAL.SAN CARLOS',
  'JEF.DPTAL.TUPUNGATO'
];

// Middleware para autorización de roles
function authorizeRoles(roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Acceso denegado: rol insuficiente' });
    }
    next();
  };
}

// Rutas API para Novedades
// Obtener todas las novedades
app.get('/novedades', authenticateToken, async (req, res) => {
  try {
    let novedades;
    
    // Define a map for roles to their respective dependencies
    const roleDependencies = {
      'OFICIAL DE 15': 'comisaria_15',
      'OFICIAL DE 20': 'comisaria_20',
      'OFICIAL DE 65': 'comisaria_65',
      'OFICIAL DE 18': 'comisaria_18',
      'OFICIAL MANZANO HISTORICO': 'subcomisaria_el_manzano',
      'OFICIAL CORDON DEL PLATA': 'subcomisaria_cordon_del_plata',
    };

    // Define specific dependency groups for JEF.DTAL roles
    const jefDtalDependencies = {
      'JEF.DPTAL.TUNUYAN': ['comisaria_15', 'comisaria_65', 'subcomisaria_el_manzano'],
      'JEF.DPTAL.SAN CARLOS': ['comisaria_18', 'comisaria_41'],
      'JEF.DPTAL.TUPUNGATO': ['comisaria_20', 'subcomisaria_cordon_del_plata', 'subcomisaria_san_jose'],
    };

    const userRole = req.user.role;

    if (roleDependencies[userRole]) {
      novedades = await Novedad.findAll({
        where: { dependencia: roleDependencies[userRole] }
      });
    } else if (jefDtalDependencies[userRole]) {
      novedades = await Novedad.findAll({
        where: {
          [Sequelize.Op.or]: jefDtalDependencies[userRole].map(dep => ({ dependencia: dep }))
        }
      });
    } else {
      // For admin, user-oficiales, and other roles, show all novedades
      novedades = await Novedad.findAll();
    }
    
    res.json(novedades);
  } catch (error) {
    logger.error('Error al obtener novedades', { error: error.message, userId: req.user.id });
    next(error);
  }
});

// Guardar una nueva novedad
app.post('/novedades', authenticateToken, authorizeRoles(ALL_OFFICIAL_ROLES), async (req, res, next) => {
  const newNovedadData = req.body;
  logger.debug('Intento de crear nueva novedad', { 
    userId: req.user.id, 
    username: req.user.username,
    dependencia: newNovedadData.dependencia 
  });
  
  try {
    const newNovedad = await Novedad.create(newNovedadData);
    logger.info('Novedad creada exitosamente', { 
      novedadId: newNovedad.id, 
      createdBy: req.user.username 
    });
    res.status(201).json(newNovedad);
  } catch (error) {
    logger.error('Error al guardar nueva novedad', { 
      error: error.message, 
      errors: error.errors,
      userId: req.user.id 
    });
    next(error);
  }
});

// Actualizar una novedad existente
app.put('/novedades/:id', authenticateToken, authorizeRoles(ALL_OFFICIAL_ROLES), async (req, res, next) => {
  const novedadId = req.params.id;
  const updatedNovedadData = req.body;

  logger.debug('Intento de actualizar novedad', { 
    novedadId, 
    userId: req.user.id 
  });

  try {
    const updatedRowsCount = await Novedad.update(updatedNovedadData, {
      where: { id: novedadId },
    });

    if (updatedRowsCount > 0) {
      const updatedNovedad = await Novedad.findByPk(novedadId);
      logger.info('Novedad actualizada exitosamente', { 
        novedadId, 
        updatedBy: req.user.username 
      });
      res.json(updatedNovedad);
    } else {
      logger.warn('Intento de actualizar novedad inexistente', { novedadId });
      res.status(404).json({ message: 'Novedad no encontrada' });
    }
  } catch (error) {
    logger.error('Error al actualizar novedad', { 
      error: error.message, 
      novedadId,
      userId: req.user.id 
    });
    next(error);
  }
});

// Eliminar una novedad
app.delete('/novedades/:id', authenticateToken, authorizeRoles(ALL_OFFICIAL_ROLES), async (req, res, next) => {
  const novedadId = req.params.id;

  logger.debug('Intento de eliminar novedad', { 
    novedadId, 
    userId: req.user.id 
  });

  try {
    const deletedRowCount = await Novedad.destroy({ where: { id: novedadId } });

    if (deletedRowCount > 0) {
      logger.info('Novedad eliminada exitosamente', { 
        novedadId, 
        deletedBy: req.user.username 
      });
      res.json({ message: 'Novedad eliminada exitosamente' });
    } else {
      logger.warn('Intento de eliminar novedad inexistente', { novedadId });
      res.status(404).json({ message: 'Novedad no encontrada' });
    }
  } catch (error) {
    logger.error('Error al eliminar novedad', { 
      error: error.message, 
      novedadId,
      userId: req.user.id 
    });
    next(error);
  }
});

// Ruta de registro
app.post('/register', authenticateToken, authorizeRoles(['admin']), async (req, res, next) => {
  logger.debug('Petición de registro recibida', { username: req.body.username, requestedBy: req.user.username });
  
  const { username, password, role, name, lastName, phone, hierarchy } = req.body;

  // Validar datos de entrada
  const validation = validateUserData({ username, password, role, phone });
  if (!validation.valid) {
    logger.warn('Intento de registro con datos inválidos', { errors: validation.errors });
    return res.status(400).json({ 
      message: 'Error de validación', 
      errors: validation.errors 
    });
  }

  try {
    const existingUser = await User.findOne({ where: { username: username } });
    if (existingUser) {
      logger.warn('Intento de registro con usuario existente', { username });
      return res.status(400).json({ message: 'El nombre de usuario ya existe' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({
      username,
      password: hashedPassword,
      role: role || 'user',
      name: name || null,
      lastName: lastName || null,
      phone: phone || null,
      hierarchy: hierarchy || null,
    });

    logger.info('Usuario registrado exitosamente', { 
      username: newUser.username, 
      role: newUser.role,
      createdBy: req.user.username 
    });

    res.status(201).json({
      message: 'Usuario registrado exitosamente',
      user: {
        id: newUser.id,
        username: newUser.username,
        role: newUser.role,
        name: newUser.name,
        lastName: newUser.lastName,
        phone: newUser.phone,
        hierarchy: newUser.hierarchy,
      }
    });
  } catch (error) {
    logger.error('Error al registrar usuario', { error: error.message, username });
    next(error);
  }
});

// Ruta de inicio de sesión
app.post('/login', async (req, res, next) => {
  const { username, password } = req.body;
  logger.debug('Intento de login recibido', { username });

  if (!username || !password) {
    logger.warn('Intento de login sin credenciales completas');
    return res.status(400).json({ message: 'Se requieren nombre de usuario y contraseña' });
  }

  try {
    const user = await User.findOne({ where: { username: username } });
    if (!user) {
      logger.warn('Intento de login con usuario inexistente', { username });
      return res.status(401).json({ message: 'Credenciales inválidas' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      logger.warn('Intento de login con contraseña incorrecta', { username });
      return res.status(401).json({ message: 'Credenciales inválidas' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    logger.info('Login exitoso', { username: user.username, role: user.role });
    res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
  } catch (error) {
    logger.error('Error al iniciar sesión', { error: error.message, username });
    next(error);
  }
});

// Rate limiting en endpoints sensibles
const authLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutos por defecto
  max: parseInt(process.env.RATE_LIMIT_MAX) || 100, // 100 intentos por ventana
  message: 'Demasiados intentos. Por favor, inténtalo más tarde.',
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn('Rate limit excedido', { ip: req.ip, path: req.path });
    res.status(429).json({ 
      message: 'Demasiados intentos. Por favor, inténtalo más tarde.' 
    });
  },
});
app.use(['/login', '/register'], authLimiter);

// Forzar HTTPS en producción detrás de proxy
if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
  app.use((req, res, next) => {
    const proto = req.headers['x-forwarded-proto'];
    if (proto && proto !== 'https') {
      return res.redirect(301, 'https://' + req.headers.host + req.originalUrl);
    }
    next();
  });
}

// Ruta para eliminar un usuario (solo accesible por administradores)
app.delete('/users/:id', authenticateToken, authorizeRoles(['admin']), async (req, res, next) => {
  const userId = req.params.id;

  logger.debug('Intento de eliminar usuario', { 
    userId, 
    requestedBy: req.user.username 
  });

  try {
    const deletedRowCount = await User.destroy({ where: { id: userId } });

    if (deletedRowCount > 0) {
      logger.info('Usuario eliminado exitosamente', { 
        userId, 
        deletedBy: req.user.username 
      });
      res.json({ message: 'Usuario eliminado exitosamente' });
    } else {
      logger.warn('Intento de eliminar usuario inexistente', { userId });
      res.status(404).json({ message: 'Usuario no encontrado' });
    }
  } catch (error) {
    logger.error('Error al eliminar usuario', { 
      error: error.message, 
      userId 
    });
    next(error);
  }
});

// Ruta para obtener todos los usuarios (solo accesible por administradores)
app.get('/users', authenticateToken, authorizeRoles(['admin']), async (req, res, next) => {
  try {
    const users = await User.findAll({ attributes: { exclude: ['password'] } });
    logger.debug('Lista de usuarios obtenida', { 
      count: users.length, 
      requestedBy: req.user.username 
    });
    res.json(users);
  } catch (error) {
    logger.error('Error al obtener usuarios', { 
      error: error.message, 
      userId: req.user.id 
    });
    next(error);
  }
});

// Nuevas rutas protegidas para "Usuario-Oficiales", "admin", "OFICIAL DE 15", "OFICIAL DE 20", "OFICIAL DE 65", "OFICIAL DE 18", "OFICIAL MANZANO HISTORICO", "OFICIAL CORDON DEL PLATA", "JEF.DTAL.TUNUYAN" y "JEF.DTAL.SAN CARLOS"
app.get('/novedades_parte', authenticateToken, authorizeRoles(ALL_OFFICIAL_ROLES), (req, res) => {
  res.json({ message: `Bienvenido a Parte de Novedades, ${req.user.username}!` });
});

app.get('/dashboard', authenticateToken, authorizeRoles(['admin', 'JEF.DPTAL.TUNUYAN', 'JEF.DPTAL.SAN CARLOS', 'JEF.DPTAL.TUPUNGATO']), (req, res) => {
  res.json({ message: `Bienvenido al Dashboard, ${req.user.username}!` });
});

app.get('/ver_novedades', authenticateToken, authorizeRoles(ALL_OFFICIAL_ROLES), (req, res) => {
  res.json({ message: `Bienvenido a Ver Partes de Novedades, ${req.user.username}!` });
});

// Ruta general (sin protección o solo para propósitos informativos)
app.get('/', (req, res) => {
  res.send('Servidor backend funcionando!');
});

async function startServer() {
  try {
    await syncDB(); // Asegurarse de que la BD esté lista antes de iniciar
    
    // Programar backups automáticos
    const backupFrequency = process.env.BACKUP_FREQUENCY || 'daily';
    scheduleBackups(backupFrequency);
    logger.info('Sistema de backups programado', { frequency: backupFrequency });
    
    // Middleware de manejo de errores (debe ir al final, antes de listen)
    app.use(validationErrorHandler);
    app.use(notFoundHandler);
    app.use(errorHandler);
    
    app.listen(PORT, () => {
      logger.info(`Servidor corriendo en el puerto ${PORT}`, { 
        environment: process.env.NODE_ENV || 'development',
        port: PORT 
      });
    });
  } catch (error) {
    logger.error('No se pudo iniciar el servidor', { error: error.message });
    process.exit(1);
  }
}

startServer();
