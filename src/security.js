// Security utilities for enhanced authentication and protection
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');

// Password validation rules
const PASSWORD_RULES = {
    minLength: 8,
    maxLength: 128,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
    forbiddenPatterns: [
        /password/i,
        /123456/i,
        /qwerty/i,
        /admin/i,
        /user/i,
        /login/i
    ]
};

// Username validation rules
const USERNAME_RULES = {
    minLength: 3,
    maxLength: 30,
    allowedChars: /^[a-zA-Z0-9_-]+$/,
    forbiddenWords: ['admin', 'root', 'administrator', 'system', 'null', 'undefined']
};

// Password strength calculation
function calculatePasswordStrength(password) {
    let score = 0;
    let feedback = [];
    
    // Length check
    if (password.length >= PASSWORD_RULES.minLength) {
        score += 20;
    } else {
        feedback.push(`Password must be at least ${PASSWORD_RULES.minLength} characters long`);
    }
    
    // Character variety checks
    if (/[a-z]/.test(password)) {
        score += 20;
    } else {
        feedback.push('Password must contain at least one lowercase letter');
    }
    
    if (/[A-Z]/.test(password)) {
        score += 20;
    } else {
        feedback.push('Password must contain at least one uppercase letter');
    }
    
    if (/[0-9]/.test(password)) {
        score += 20;
    } else {
        feedback.push('Password must contain at least one number');
    }
    
    if (/[^a-zA-Z0-9]/.test(password)) {
        score += 20;
    } else {
        feedback.push('Password must contain at least one special character');
    }
    
    // Check for forbidden patterns
    for (const pattern of PASSWORD_RULES.forbiddenPatterns) {
        if (pattern.test(password)) {
            score -= 30;
            feedback.push('Password contains common patterns that are not allowed');
            break;
        }
    }
    
    // Determine strength level
    let strength;
    if (score >= 80) {
        strength = 'Very Strong';
    } else if (score >= 60) {
        strength = 'Strong';
    } else if (score >= 40) {
        strength = 'Medium';
    } else if (score >= 20) {
        strength = 'Weak';
    } else {
        strength = 'Very Weak';
    }
    
    return {
        score,
        strength,
        feedback,
        isValid: score >= 60 && feedback.length === 0
    };
}

// Validate password
function validatePassword(password) {
    const result = calculatePasswordStrength(password);
    
    // Additional checks
    if (password.length > PASSWORD_RULES.maxLength) {
        result.feedback.push(`Password must not exceed ${PASSWORD_RULES.maxLength} characters`);
        result.isValid = false;
    }
    
    return result;
}

// Validate username
function validateUsername(username) {
    const errors = [];
    
    if (!username || username.trim().length === 0) {
        errors.push('Username is required');
        return { isValid: false, errors };
    }
    
    const trimmedUsername = username.trim();
    
    if (trimmedUsername.length < USERNAME_RULES.minLength) {
        errors.push(`Username must be at least ${USERNAME_RULES.minLength} characters long`);
    }
    
    if (trimmedUsername.length > USERNAME_RULES.maxLength) {
        errors.push(`Username must not exceed ${USERNAME_RULES.maxLength} characters`);
    }
    
    if (!USERNAME_RULES.allowedChars.test(trimmedUsername)) {
        errors.push('Username can only contain letters, numbers, underscores, and hyphens');
    }
    
    for (const word of USERNAME_RULES.forbiddenWords) {
        if (trimmedUsername.toLowerCase().includes(word)) {
            errors.push(`Username cannot contain "${word}"`);
            break;
        }
    }
    
    return {
        isValid: errors.length === 0,
        errors,
        sanitized: trimmedUsername
    };
}

// Rate limiting configurations
const createRateLimit = (windowMs, max, message) => {
    return rateLimit({
        windowMs,
        max,
        message: { error: message },
        standardHeaders: true,
        legacyHeaders: false,
        handler: (req, res) => {
            res.status(429).json({
                error: message,
                retryAfter: Math.round(windowMs / 1000)
            });
        }
    });
};

// Security middleware
const securityMiddleware = {
    // Login rate limiting
    loginLimiter: createRateLimit(
        15 * 60 * 1000, // 15 minutes
        5, // 5 attempts per window
        'Too many login attempts. Please try again in 15 minutes.'
    ),
    
    // Signup rate limiting
    signupLimiter: createRateLimit(
        60 * 60 * 1000, // 1 hour
        3, // 3 signups per hour
        'Too many signup attempts. Please try again in 1 hour.'
    ),
    
    // Admin login rate limiting
    adminLimiter: createRateLimit(
        15 * 60 * 1000, // 15 minutes
        3, // 3 attempts per window
        'Too many admin login attempts. Please try again in 15 minutes.'
    ),
    
    // General API rate limiting
    apiLimiter: createRateLimit(
        15 * 60 * 1000, // 15 minutes
        100, // 100 requests per window
        'Too many requests. Please try again later.'
    )
};

// Input sanitization
function sanitizeInput(input) {
    if (typeof input !== 'string') return input;
    
    return input
        .trim()
        .replace(/[<>]/g, '') // Remove potential HTML tags
        .substring(0, 1000); // Limit length
}

// Session security configuration
const sessionConfig = {
    secret: process.env.SESSION_SECRET || 'your-super-secret-key-change-this-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production', // HTTPS only in production
        httpOnly: true, // Prevent XSS
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        sameSite: 'strict' // CSRF protection
    },
    name: 'sessionId' // Don't use default session name
};

// CSRF protection token generation
function generateCSRFToken() {
    return require('crypto').randomBytes(32).toString('hex');
}

// Validate CSRF token
function validateCSRFToken(req, token) {
    const sessionToken = req.session.csrfToken;
    return sessionToken && sessionToken === token;
}

// Enhanced password hashing
async function hashPassword(password) {
    const saltRounds = 12; // Increased from default 10
    return await bcrypt.hash(password, saltRounds);
}

// Password comparison with timing attack protection
async function comparePassword(password, hash) {
    return await bcrypt.compare(password, hash);
}

// Account lockout mechanism
const accountLockouts = new Map();

function isAccountLocked(username) {
    const lockout = accountLockouts.get(username);
    if (!lockout) return false;
    
    if (Date.now() - lockout.timestamp > 15 * 60 * 1000) { // 15 minutes
        accountLockouts.delete(username);
        return false;
    }
    
    return lockout.attempts >= 5;
}

function recordFailedAttempt(username) {
    const lockout = accountLockouts.get(username) || { attempts: 0, timestamp: Date.now() };
    lockout.attempts++;
    lockout.timestamp = Date.now();
    accountLockouts.set(username, lockout);
}

function clearFailedAttempts(username) {
    accountLockouts.delete(username);
}

// Security headers middleware
function securityHeaders(req, res, next) {
    // Prevent clickjacking
    res.setHeader('X-Frame-Options', 'DENY');
    
    // Prevent MIME type sniffing
    res.setHeader('X-Content-Type-Options', 'nosniff');
    
    // XSS protection
    res.setHeader('X-XSS-Protection', '1; mode=block');
    
    // Strict transport security (HTTPS only)
    if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }
    
    // Content security policy
    res.setHeader('Content-Security-Policy', 
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; " +
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; " +
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; " +
        "img-src 'self' data:; " +
        "connect-src 'self'"
    );
    
    next();
}

module.exports = {
    validatePassword,
    validateUsername,
    calculatePasswordStrength,
    securityMiddleware,
    sanitizeInput,
    sessionConfig,
    generateCSRFToken,
    validateCSRFToken,
    hashPassword,
    comparePassword,
    isAccountLocked,
    recordFailedAttempt,
    clearFailedAttempts,
    securityHeaders,
    PASSWORD_RULES,
    USERNAME_RULES
};

