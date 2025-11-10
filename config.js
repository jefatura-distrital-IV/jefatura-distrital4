// Configuración centralizada para el frontend
// Este archivo se puede usar en todos los HTML para centralizar la configuración

// Determinar la URL base de la API según el entorno
function getApiBaseUrl() {
    // Si estamos en producción (HTTPS), usar la URL del servidor
    if (window.location.protocol === 'https:') {
        // En producción, usar la misma URL del servidor
        return window.location.origin;
    }
    
    // En desarrollo, usar localhost
    // También puedes usar una variable de entorno si la defines en el HTML
    const devApiUrl = window.API_BASE_URL || 'http://localhost:3001';
    return devApiUrl;
}

// Configuración global
const Config = {
    API_BASE_URL: getApiBaseUrl(),
    
    // Configuración de tokens
    TOKEN_KEY: 'jwtToken',
    USERNAME_KEY: 'loggedInUsername',
    USER_ROLE_KEY: 'userRole',
    USER_ID_KEY: 'loggedInUserId',
    
    // Configuración de retry
    MAX_RETRIES: 3,
    RETRY_DELAY: 1000, // 1 segundo
};

// Función helper para hacer peticiones HTTP con manejo de errores
async function apiRequest(url, options = {}) {
    const token = localStorage.getItem(Config.TOKEN_KEY);
    
    const defaultHeaders = {
        'Content-Type': 'application/json',
    };
    
    if (token) {
        defaultHeaders['Authorization'] = `Bearer ${token}`;
    }
    
    const config = {
        ...options,
        headers: {
            ...defaultHeaders,
            ...options.headers,
        },
    };
    
    let retries = 0;
    while (retries < Config.MAX_RETRIES) {
        try {
            const response = await fetch(`${Config.API_BASE_URL}${url}`, config);
            
            // Si la respuesta no es OK, intentar parsear el error
            if (!response.ok) {
                let errorData;
                try {
                    errorData = await response.json();
                } catch (e) {
                    errorData = { message: `Error ${response.status}: ${response.statusText}` };
                }
                
                // Si es 401 (no autorizado), redirigir al login
                if (response.status === 401) {
                    localStorage.removeItem(Config.TOKEN_KEY);
                    localStorage.removeItem(Config.USERNAME_KEY);
                    localStorage.removeItem(Config.USER_ROLE_KEY);
                    localStorage.removeItem(Config.USER_ID_KEY);
                    window.location.href = 'index.html';
                    return;
                }
                
                throw new Error(errorData.message || `Error ${response.status}`);
            }
            
            // Si la respuesta es exitosa, intentar parsear JSON
            const contentType = response.headers.get('content-type');
            if (contentType && contentType.includes('application/json')) {
                return await response.json();
            }
            
            return await response.text();
        } catch (error) {
            retries++;
            if (retries >= Config.MAX_RETRIES) {
                throw error;
            }
            // Esperar antes de reintentar
            await new Promise(resolve => setTimeout(resolve, Config.RETRY_DELAY * retries));
        }
    }
}

// Exportar configuración y funciones
if (typeof window !== 'undefined') {
    window.Config = Config;
    window.apiRequest = apiRequest;
    window.getApiBaseUrl = getApiBaseUrl;
}

