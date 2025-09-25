const express = require("express");
const path = require("path");
const bcrypt = require("bcrypt");
const session = require('express-session');
const multer = require('multer');
const fs = require('fs');
const { connectDB } = require('./config');
const { 
    validatePassword, 
    validateUsername, 
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
    securityHeaders 
} = require('./security');

const app = express();
let collection;

const ADMIN_SECRET_KEY = process.env.ADMIN_SECRET_KEY || '987654';

const uploadsDir = path.join(__dirname, '../public/uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// Multer storage configuration
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, path.join(__dirname, '../public/uploads'));
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

async function setupApp() {
    // Cart middleware
    collection = await connectDB();

    app.set('view engine', 'ejs');
    app.set('views', path.join(__dirname, '../views'));

    // Security headers
    app.use(securityHeaders);
    
    // Session configuration with enhanced security
    app.use(session(sessionConfig));
    
    // Generate CSRF token for each session
    app.use((req, res, next) => {
        if (!req.session.csrfToken) {
            req.session.csrfToken = generateCSRFToken();
        }
        res.locals.csrfToken = req.session.csrfToken;
        next();
    });

    // Cart middleware
    app.use((req, res, next) => {
        if (req.session) {
            if (!req.session.cart) req.session.cart = [];
        }
        next();
    });

    app.use(express.urlencoded({ extended: true }));
    app.use(express.json());
    app.use(express.static(path.join(__dirname, '../public')));

    // Root route to render login page
    app.get('/', (req, res) => {
        res.render('login', { cartCount: req.session.cart ? req.session.cart.length : 0 });
    });

    // Admin login page route
    app.get('/admin', (req, res) => {
        res.render('adminlogin', { csrfToken: req.session.csrfToken });
    });

    // Signup GET route
    app.get('/signup', (req, res) => {
        res.render('signup', { csrfToken: req.session.csrfToken });
    });

    // Login POST route with enhanced security
    app.post('/login', securityMiddleware.loginLimiter, async (req, res) => {
        const { username, password, csrfToken } = req.body;
        
        // CSRF protection
        if (!validateCSRFToken(req, csrfToken)) {
            return res.status(403).json({ error: 'Invalid CSRF token' });
        }
        
        // Input sanitization
        const sanitizedUsername = sanitizeInput(username);
        const sanitizedPassword = sanitizeInput(password);
        
        // Validate input
        const usernameValidation = validateUsername(sanitizedUsername);
        if (!usernameValidation.isValid) {
            return res.status(400).json({ error: 'Invalid username format' });
        }
        
        try {
            // Check if account is locked
            if (isAccountLocked(sanitizedUsername)) {
                return res.status(423).json({ 
                    error: 'Account temporarily locked due to too many failed attempts. Please try again in 15 minutes.' 
                });
            }
            
            const user = await collection.findOne({ name: sanitizedUsername });
            if (!user) {
                recordFailedAttempt(sanitizedUsername);
                console.log('Login failed: user not found');
                return res.status(401).json({ error: "Invalid credentials" });
            }
            
            const match = await comparePassword(sanitizedPassword, user.password);
            if (!match) {
                recordFailedAttempt(sanitizedUsername);
                console.log('Login failed: password mismatch');
                return res.status(401).json({ error: "Invalid credentials" });
            }
            
            // Clear failed attempts on successful login
            clearFailedAttempts(sanitizedUsername);
            
            // Regenerate session ID for security
            req.session.regenerate((err) => {
                if (err) {
                    console.error('Session regeneration error:', err);
                    return res.status(500).json({ error: 'Session error' });
                }
                
                req.session.username = user.name;
                req.session.profilePicture = user.profilePicture || '/default-profile.png';
                req.session.loginTime = Date.now();
                if (!req.session.cart) req.session.cart = [];
                
                console.log('Login success, redirecting to /home');
                res.redirect('/home');
            });
        } catch (err) {
            console.error('Login error:', err);
            res.status(500).json({ error: "Login error" });
        }
    });

    // Signout route
    app.get('/signout', (req, res) => {
        req.session.destroy(() => {
            res.redirect('/');
        });
    });

    // Admin logout route
    app.get('/admin/logout', (req, res) => {
        req.session.destroy(() => {
            res.redirect('/admin');
        });
    });

    // Profile GET route
    app.get('/profile', async (req, res) => {
        if (!req.session.username) return res.redirect('/');
        try {
            const user = await collection.findOne({ name: req.session.username });
            if (!user) return res.redirect('/signout');
            res.render('profile', {
                username: user.name,
                bio: user.bio || '',
                profilePicture: user.profilePicture || '/default-profile.png'
            });
        } catch (err) {
            res.redirect('/signout');
        }
    });

    // Home route (protected)
    app.get('/home', (req, res) => {
        if (!req.session.username) return res.redirect('/');
        res.render('home', { 
            username: req.session.username,
            profilePicture: req.session.profilePicture,
            cartCount: req.session.cart ? req.session.cart.length : 0 
        });
    });


    // Enhanced signup with stronger security
    app.post("/signup", securityMiddleware.signupLimiter, upload.single("profilePicture"), async (req, res) => {
        try {
            const { username, password, bio, csrfToken } = req.body;
            
            // CSRF protection
            if (!validateCSRFToken(req, csrfToken)) {
                return res.status(403).json({ error: 'Invalid CSRF token' });
            }
            
            // Input sanitization
            const sanitizedUsername = sanitizeInput(username);
            const sanitizedPassword = sanitizeInput(password);
            const sanitizedBio = sanitizeInput(bio);
            
            // Validate username
            const usernameValidation = validateUsername(sanitizedUsername);
            if (!usernameValidation.isValid) {
                return res.status(400).json({ 
                    error: 'Invalid username', 
                    details: usernameValidation.errors 
                });
            }
            
            // Validate password
            const passwordValidation = validatePassword(sanitizedPassword);
            if (!passwordValidation.isValid) {
                return res.status(400).json({ 
                    error: 'Password does not meet security requirements', 
                    details: passwordValidation.feedback 
                });
            }
            
            // Check for existing user
            const existingUser = await collection.findOne({ name: sanitizedUsername });
            if (existingUser) {
                if (req.file && req.file.path && fs.existsSync(req.file.path)) {
                    fs.unlinkSync(req.file.path);
                }
                console.log('Signup failed: user already exists');
                return res.status(400).json({ error: "Username already exists" });
            }
            
            // Hash password with enhanced security
            const hashedPassword = await hashPassword(sanitizedPassword);
            
            // Create user with sanitized data
            await collection.insertOne({
                name: sanitizedUsername,
                password: hashedPassword,
                bio: sanitizedBio || '',
                profilePicture: req.file ? `/uploads/${req.file.filename}` : '',
                createdAt: new Date(),
                lastLogin: null
            });
            
            // Regenerate session ID for security
            req.session.regenerate((err) => {
                if (err) {
                    console.error('Session regeneration error:', err);
                    return res.status(500).json({ error: 'Session error' });
                }
                
                // Auto-login after signup
                req.session.username = sanitizedUsername;
                req.session.profilePicture = req.file ? `/uploads/${req.file.filename}` : '/default-profile.png';
                req.session.loginTime = Date.now();
                req.session.cart = [];
                
                console.log('Signup success, redirecting to /home');
                res.redirect("/home");
            });
        } catch (err) {
            if (req.file && req.file.path && fs.existsSync(req.file.path)) {
                fs.unlinkSync(req.file.path);
            }
            console.error('Signup error:', err);
            res.status(500).json({ error: "Error creating user" });
        }
    });

    // Enhanced admin login POST with security
    app.post("/admin", securityMiddleware.adminLimiter, async (req, res) => {
        const { adminKey, csrfToken } = req.body;
        
        // CSRF protection
        if (!validateCSRFToken(req, csrfToken)) {
            return res.status(403).json({ error: 'Invalid CSRF token' });
        }
        
        // Input sanitization
        const sanitizedAdminKey = sanitizeInput(adminKey);
        
        if (sanitizedAdminKey !== ADMIN_SECRET_KEY) {
            console.log('Admin login failed: invalid key');
            return res.status(403).json({ error: "Invalid Admin Key" });
        }
        
        // Regenerate session ID for security
        req.session.regenerate((err) => {
            if (err) {
                console.error('Session regeneration error:', err);
                return res.status(500).json({ error: 'Session error' });
            }
            
            req.session.isAdmin = true;
            req.session.adminLoginTime = Date.now();
            res.redirect('/admin/dashboard');
        });
    });

    // Admin middleware
    const checkAdmin = (req, res, next) => {
        if (req.session.isAdmin) {
            next();
        } else {
            res.redirect("/admin");
        }
    };

    // Admin dashboard GET (after login)
    app.get('/admin/dashboard', checkAdmin, async (req, res) => {
        try {
            const users = await collection.find({}, { projection: { name: 1, bio: 1, profilePicture: 1 } }).toArray();
            res.render("adminDashboard", { users });
        } catch (err) {
            res.status(500).send("Database error");
        }
    });

    // Protected admin routes
    app.get("/createuser", checkAdmin, (req, res) => res.render("createuser"));

    // Enhanced admin create user with security
    app.post("/admin/create", checkAdmin, async (req, res) => {
        const { username, password, csrfToken } = req.body;
        
        // CSRF protection
        if (!validateCSRFToken(req, csrfToken)) {
            return res.status(403).json({ error: 'Invalid CSRF token' });
        }
        
        // Input sanitization
        const sanitizedUsername = sanitizeInput(username);
        const sanitizedPassword = sanitizeInput(password);
        
        // Validate username
        const usernameValidation = validateUsername(sanitizedUsername);
        if (!usernameValidation.isValid) {
            return res.status(400).json({ 
                error: 'Invalid username', 
                details: usernameValidation.errors 
            });
        }
        
        // Validate password
        const passwordValidation = validatePassword(sanitizedPassword);
        if (!passwordValidation.isValid) {
            return res.status(400).json({ 
                error: 'Password does not meet security requirements', 
                details: passwordValidation.feedback 
            });
        }
        
        try {
            const existingUser = await collection.findOne({ name: sanitizedUsername });
            if (existingUser) return res.status(400).json({ error: "User already exists" });
            
            const hashedPassword = await hashPassword(sanitizedPassword);
            await collection.insertOne({ 
                name: sanitizedUsername, 
                password: hashedPassword, 
                bio: '', 
                profilePicture: '',
                createdAt: new Date(),
                lastLogin: null
            });
            res.redirect('/admin/dashboard?message=User created successfully!&type=success');
        } catch (err) {
            console.error('Admin create user error:', err);
            res.redirect('/admin/dashboard?message=Error creating user.&type=error');
        }
    });

    // Enhanced admin edit user with security
    app.post("/admin/edit", checkAdmin, async (req, res) => {
        const { id, username, password, csrfToken } = req.body;
        
        // CSRF protection
        if (!validateCSRFToken(req, csrfToken)) {
            return res.status(403).json({ error: 'Invalid CSRF token' });
        }
        
        // Input sanitization
        const sanitizedUsername = sanitizeInput(username);
        const sanitizedPassword = sanitizeInput(password);
        
        // Validate username
        const usernameValidation = validateUsername(sanitizedUsername);
        if (!usernameValidation.isValid) {
            return res.status(400).json({ 
                error: 'Invalid username', 
                details: usernameValidation.errors 
            });
        }
        
        try {
            const update = { name: sanitizedUsername };
            if (sanitizedPassword && sanitizedPassword.trim() !== '') {
                // Validate password if provided
                const passwordValidation = validatePassword(sanitizedPassword);
                if (!passwordValidation.isValid) {
                    return res.status(400).json({ 
                        error: 'Password does not meet security requirements', 
                        details: passwordValidation.feedback 
                    });
                }
                update.password = await hashPassword(sanitizedPassword);
            }
            
            await collection.updateOne({ _id: require('mongodb').ObjectId(id) }, { $set: update });
            res.redirect('/admin/dashboard?message=User updated successfully!&type=success');
        } catch (err) {
            console.error('Admin edit user error:', err);
            res.redirect('/admin/dashboard?message=Error updating user.&type=error');
        }
    });

    // Enhanced admin delete user with security
    app.post("/admin/delete", checkAdmin, async (req, res) => {
        const { id, csrfToken } = req.body;
        
        // CSRF protection
        if (!validateCSRFToken(req, csrfToken)) {
            return res.status(403).json({ error: 'Invalid CSRF token' });
        }
        
        // Input sanitization
        const sanitizedId = sanitizeInput(id);
        
        try {
            // Validate ObjectId format
            if (!require('mongodb').ObjectId.isValid(sanitizedId)) {
                return res.status(400).json({ error: 'Invalid user ID' });
            }
            
            const result = await collection.deleteOne({ _id: require('mongodb').ObjectId(sanitizedId) });
            
            if (result.deletedCount === 0) {
                return res.status(404).json({ error: 'User not found' });
            }
            
            res.redirect('/admin/dashboard?message=User deleted successfully!&type=success');
        } catch (err) {
            console.error('Admin delete user error:', err);
            res.redirect('/admin/dashboard?message=Error deleting user.&type=error');
        }
    });

    // Admin search user
    app.get("/admin/search", checkAdmin, async (req, res) => {
        const { username } = req.query;
        try {
            const users = await collection.find(
                username ? { name: { $regex: username, $options: 'i' } } : {},
                { projection: { name: 1, bio: 1, profilePicture: 1 } }
            ).toArray();
            res.render("adminDashboard", { users });
        } catch (err) {
            res.status(500).send("Database error");
        }
    });

    // Improved profile update
    app.post("/profile/update", upload.single("profilePicture"), async (req, res) => {
        if (!req.session.username) return res.status(401).send("Unauthorized");
        try {
            const update = { bio: req.body.bio };
            if (req.file) {
                update.profilePicture = `/uploads/${req.file.filename}`;
                const user = await collection.findOne({ name: req.session.username });
                if (user && user.profilePicture) {
                    const oldPath = path.join(__dirname, '../public', user.profilePicture);
                    if (fs.existsSync(oldPath)) {
                        fs.unlinkSync(oldPath);
                    }
                }
            }
            await collection.findOneAndUpdate(
                { name: req.session.username },
                { $set: update },
                { returnDocument: 'after' }
            );
            res.redirect("/profile");
        } catch (err) {
            if (req.file && req.file.path && fs.existsSync(req.file.path)) {
                fs.unlinkSync(req.file.path);
            }
            res.status(500).send("Update failed");
        }
    });

    // Change password GET route
    app.get('/profile/change-password', (req, res) => {
        if (!req.session.username) return res.redirect('/');
        res.render('changePassword', { username: req.session.username });
    });

    // Change password POST route
    app.post('/profile/change-password', async (req, res) => {
        if (!req.session.username) return res.redirect('/');

        const { oldPassword, newPassword, confirmPassword } = req.body;

        // Input sanitization
        const sanitizedOldPassword = sanitizeInput(oldPassword);
        const sanitizedNewPassword = sanitizeInput(newPassword);

        try {
            const user = await collection.findOne({ name: req.session.username });

            if (!user) {
                console.log('Change password failed: user not found');
                return res.status(400).json({ error: "User not found" });
            }

            const match = await comparePassword(sanitizedOldPassword, user.password);

            if (!match) {
                console.log('Change password failed: invalid old password');
                return res.status(400).json({ error: "Invalid old password" });
            }

            if (newPassword !== confirmPassword) {
                console.log('Change password failed: new passwords do not match');
                return res.status(400).json({ error: "New passwords do not match" });
            }

            const passwordValidation = validatePassword(sanitizedNewPassword);
            if (!passwordValidation.isValid) {
                return res.status(400).json({
                    error: 'Password does not meet security requirements',
                    details: passwordValidation.feedback
                });
            }

            const hashedPassword = await hashPassword(sanitizedNewPassword);

            await collection.updateOne({ name: req.session.username }, { $set: { password: hashedPassword } });

            console.log('Password changed successfully');
            res.redirect('/profile');

        } catch (err) {
            console.error('Change password error:', err);
            res.status(500).json({ error: "Error changing password" });
        }
    });

    return app;
}

module.exports = { setupApp, app };
