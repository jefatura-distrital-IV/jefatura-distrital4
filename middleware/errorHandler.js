// Middleware centralizado para manejo de errores
// Este archivo contiene funciones para manejar errores de manera consistente

const errorHandler = (err, req, res, next) => {
  // Log del error
  console.error('Error:', {
    message: err.message,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
    timestamp: new Date().toISOString(),
  });

  // Determinar el código de estado
  const statusCode = err.statusCode || err.status || 500;

  // Mensaje de error para el cliente
  let message = err.message || 'Error interno del servidor';
  
  // En producción, ocultar detalles de errores internos
  if (statusCode === 500 && process.env.NODE_ENV === 'production') {
    message = 'Error interno del servidor. Por favor, contacte al administrador.';
  }

  // Respuesta al cliente
  res.status(statusCode).json({
    success: false,
    message: message,
    ...(process.env.NODE_ENV === 'development' && { 
      error: err.message,
      stack: err.stack 
    }),
  });
};

// Middleware para manejar rutas no encontradas
const notFoundHandler = (req, res, next) => {
  const error = new Error(`Ruta no encontrada: ${req.originalUrl}`);
  error.status = 404;
  next(error);
};

// Middleware para validar errores de validación
const validationErrorHandler = (err, req, res, next) => {
  if (err.name === 'ValidationError' || err.name === 'SequelizeValidationError') {
    const errors = err.errors || (err.inner ? err.inner.map(e => ({ message: e.message })) : []);
    return res.status(400).json({
      success: false,
      message: 'Error de validación',
      errors: errors.map(e => e.message || e),
    });
  }
  next(err);
};

module.exports = {
  errorHandler,
  notFoundHandler,
  validationErrorHandler,
};

