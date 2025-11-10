// Validadores para datos de usuario
// Estos validadores se pueden usar en las rutas para validar datos de entrada

const validateUsername = (username) => {
  if (!username || typeof username !== 'string') {
    return { valid: false, error: 'El nombre de usuario es requerido' };
  }
  
  if (username.length < 3 || username.length > 30) {
    return { valid: false, error: 'El nombre de usuario debe tener entre 3 y 30 caracteres' };
  }
  
  if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    return { valid: false, error: 'El nombre de usuario solo puede contener letras, números y guiones bajos' };
  }
  
  return { valid: true };
};

const validatePassword = (password) => {
  if (!password || typeof password !== 'string') {
    return { valid: false, error: 'La contraseña es requerida' };
  }
  
  if (password.length < 6) {
    return { valid: false, error: 'La contraseña debe tener al menos 6 caracteres' };
  }
  
  // Validar complejidad (opcional)
  // if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(password)) {
  //   return { valid: false, error: 'La contraseña debe contener al menos una letra mayúscula, una minúscula y un número' };
  // }
  
  return { valid: true };
};

const validateEmail = (email) => {
  if (!email) {
    return { valid: true }; // Email es opcional
  }
  
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return { valid: false, error: 'El formato del email no es válido' };
  }
  
  return { valid: true };
};

const validatePhone = (phone) => {
  if (!phone) {
    return { valid: true }; // Teléfono es opcional
  }
  
  // Validar formato básico de teléfono (solo números, espacios, guiones, paréntesis)
  const phoneRegex = /^[\d\s\-\(\)]+$/;
  if (!phoneRegex.test(phone)) {
    return { valid: false, error: 'El formato del teléfono no es válido' };
  }
  
  return { valid: true };
};

const validateRole = (role) => {
  const validRoles = [
    'admin',
    'user',
    'user-oficiales',
    'OFICIAL DE 15',
    'OFICIAL DE 18',
    'OFICIAL DE 20',
    'OFICIAL DE 65',
    'OFICIAL DE 41',
    'OFICIAL MANZANO HISTORICO',
    'OFICIAL CORDON DEL PLATA',
    'OFICIAL DE SAN JOSE',
    'JEF.DPTAL.TUNUYAN',
    'JEF.DPTAL.SAN CARLOS',
    'JEF.DPTAL.TUPUNGATO',
  ];
  
  if (!role) {
    return { valid: false, error: 'El rol es requerido' };
  }
  
  if (!validRoles.includes(role)) {
    return { valid: false, error: `El rol debe ser uno de: ${validRoles.join(', ')}` };
  }
  
  return { valid: true };
};

const validateUserData = (userData) => {
  const errors = [];
  
  // Validar username
  const usernameValidation = validateUsername(userData.username);
  if (!usernameValidation.valid) {
    errors.push(usernameValidation.error);
  }
  
  // Validar password (si se está creando o actualizando)
  if (userData.password) {
    const passwordValidation = validatePassword(userData.password);
    if (!passwordValidation.valid) {
      errors.push(passwordValidation.error);
    }
  }
  
  // Validar email (si existe)
  if (userData.email) {
    const emailValidation = validateEmail(userData.email);
    if (!emailValidation.valid) {
      errors.push(emailValidation.error);
    }
  }
  
  // Validar phone (si existe)
  if (userData.phone) {
    const phoneValidation = validatePhone(userData.phone);
    if (!phoneValidation.valid) {
      errors.push(phoneValidation.error);
    }
  }
  
  // Validar role (si existe)
  if (userData.role) {
    const roleValidation = validateRole(userData.role);
    if (!roleValidation.valid) {
      errors.push(roleValidation.error);
    }
  }
  
  return {
    valid: errors.length === 0,
    errors,
  };
};

module.exports = {
  validateUsername,
  validatePassword,
  validateEmail,
  validatePhone,
  validateRole,
  validateUserData,
};

