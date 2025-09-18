<<<<<<< HEAD
const express = require('express');
=======
const express = require("express");
const path = require("path");
const bcrypt = require("bcrypt");
const collection = require("./config");

>>>>>>> ec867de18a80236e2b318efa1eba9ec97ba5b1d7
const app = express();
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const { connectDB } = require('./config');
const products = require('./products');
let collection;


const ADMIN_SECRET_KEY = process.env.ADMIN_SECRET_KEY || '987654';

const uploadsDir = path.join(__dirname, '../public/uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

<<<<<<< HEAD
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

async function startServer() {
    // Cart middleware
    app.use((req, res, next) => {
        if (req.session) {
            if (!req.session.cart) req.session.cart = [];
        }
        next();
    });

    // E-commerce: Home page with products
    app.get('/home', (req, res) => {
        if (!req.session || !req.session.username) return res.redirect('/');
        res.render('home', {
            username: req.session.username,
            profilePicture: req.session.profilePicture || '/default-profile.png',
            products,
            cartCount: req.session.cart ? req.session.cart.length : 0
        });
    });

    // Product detail page
    app.get('/product/:id', (req, res) => {
        const product = products.find(p => p.id == req.params.id);
        if (!product) return res.status(404).send('Product not found');
        
        // Map product properties to match view expectations
        const viewProduct = {
            ...product,
            name: product.title,
            description: product.description || 'No description available'
        };
        
        res.render('product', { 
            product: viewProduct, 
            username: req.session.username, 
            cartCount: req.session.cart.length 
        });
    });

    // Add to cart
    app.post('/cart/add/:id', (req, res) => {
        const product = products.find(p => p.id == req.params.id);
        if (!product) return res.status(404).send('Product not found');
        req.session.cart.push(product.id);
        res.redirect('/home');
    });

    // View cart
    app.get('/cart', (req, res) => {
        const cartProducts = req.session.cart.map(id => products.find(p => p.id == id));
        res.render('cart', { cartProducts, username: req.session.username, cartCount: req.session.cart.length });
    });

    // Remove from cart
    app.post('/cart/remove/:id', (req, res) => {
        const productId = parseInt(req.params.id);
        const index = req.session.cart.indexOf(productId);
        if (index !== -1) {
            req.session.cart.splice(index, 1);
        }
        res.redirect('/cart');
    });

    // Admin login page route
    app.get('/admin', (req, res) => {
        res.render('adminlogin');
    });

    collection = await connectDB();

    app.set('view engine', 'ejs');
    app.set('views', path.join(__dirname, '../views'));

    app.use(
        session({
            secret: process.env.SESSION_SECRET || "strong-secret-key",
            resave: false,
            saveUninitialized: false,
            cookie: { secure: process.env.NODE_ENV === 'production' }
        })
    );

    app.use(express.urlencoded({ extended: true }));
    app.use(express.json());
    app.use(express.static(path.join(__dirname, '../public')));

    // Root route to render login page
    app.get('/', (req, res) => {
        res.render('login', { cartCount: req.session.cart ? req.session.cart.length : 0 });
    });

    // Signup GET route
    app.get('/signup', (req, res) => {
        res.render('signup');
    });

    // Login POST route
    app.post('/login', async (req, res) => {
        const { username, password } = req.body;
        try {
            const user = await collection.findOne({ name: username });
            if (!user) {
                console.log('Login failed: user not found');
                return res.status(401).send("Invalid credentials");
            }
            const match = await bcrypt.compare(password, user.password);
            if (!match) {
                console.log('Login failed: password mismatch');
                return res.status(401).send("Invalid credentials");
            }
            req.session.username = user.name;
            req.session.profilePicture = user.profilePicture || '/default-profile.png';
            if (!req.session.cart) req.session.cart = [];
            console.log('Login success, redirecting to /home');
            res.redirect('/home');
        } catch (err) {
            console.error('Login error:', err);
            res.status(500).send("Login error");
        }
    });

    // Signout route
    app.get('/signout', (req, res) => {
        req.session.destroy(() => {
            res.redirect('/');
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

    // About Me route
    app.get('/aboutme', (req, res) => {
        res.render('aboutme');
    });

    // ...existing code...

    // Improved signup with profile handling
    app.post("/signup", upload.single("profilePicture"), async (req, res) => {
        try {
            const { username, password, bio } = req.body;
            const profilePicture = req.file ? `/uploads/${req.file.filename}` : "";
            const existingUser = await collection.findOne({ name: username });
            if (existingUser) {
                if (req.file && req.file.path && fs.existsSync(req.file.path)) {
                    fs.unlinkSync(req.file.path);
                }
                console.log('Signup failed: user already exists');
                return res.status(400).send("User already exists");
            }
            const hashedPassword = await bcrypt.hash(password, 10);
            await collection.insertOne({
                name: username,
                password: hashedPassword,
                bio,
                profilePicture
            });
            // Auto-login after signup
            req.session.username = username;
            req.session.profilePicture = profilePicture || '/default-profile.png';
            req.session.cart = [];
            console.log('Signup success, redirecting to /home');
            res.redirect("/home");
        } catch (err) {
            if (req.file && req.file.path && fs.existsSync(req.file.path)) {
                fs.unlinkSync(req.file.path);
            }
            console.error('Signup error:', err);
            res.status(500).send("Error creating user");
        }
    });

    // Admin login POST
    app.post("/admin", async (req, res) => {
        if (req.body.adminKey !== ADMIN_SECRET_KEY) {
            return res.status(403).send("Invalid Admin Key");
        }
        req.session.isAdmin = true;
        res.redirect('/admin/dashboard');
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
=======

app.get("/", (req, res) => {
    res.render("login");
});

app.get("/signup", (req, res) => {
    res.render("signup");
});

app.post("/signup", async (req, res) => {
    const data = {
        name: req.body.username,
        password: req.body.password,
    };

    const existingUser = await collection.findOne({ name: data.name });

    if (existingUser) {
        res.send("User Already Exist, Please choose a Different Username.");
    } else {
        const saltRounds = 10;
        const hashPassword = await bcrypt.hash(data.password, saltRounds);

        data.password = hashPassword;

        const userdata = await collection.insertMany([data]);
        console.log(userdata);
        res.send("User created successfully");
    }
});

app.post("/login", async (req, res) => {
    try {
        const { username, emailId, password } = req.body;
        const check = await collection.findOne({ name: username, emailId: emailId });

        if (!check) {
            res.send("User not found");
        } else {
            const isPasswordMatch = await bcrypt.compare(password, check.password);
            if (isPasswordMatch) {
                res.render("home");
            } else {
                res.send("Wrong password");
            }
        }
    } catch {
        res.send("Wrong Details");
    }
});



app.get("/home", (req, res) => {
    res.render("home");
});

app.get("/aboutme", (req, res) => {
    res.render("aboutme");
});

app.post("/logout", (req, res) => {
    res.redirect("/");
});

const ADMIN_SECRET_KEY = "987654";

app.get("/admin", (req, res) => {
    res.render("adminlogin");
});

app.post("/admin", async (req, res) => {
    const { adminKey } = req.body;
    if (adminKey === ADMIN_SECRET_KEY) {
        const users = await collection.find({});
        res.render("adminDashboard", { users });
    } else {
        res.send("Invalid Admin Key");
    }
});

app.post("/admin/create", async (req, res) => {
    const data = {
        name: req.body.username,
        password: req.body.password,
        emailId: req.body.emailId
    };

    const existingUser = await collection.findOne({ name: data.name });

    if (existingUser) {
        res.send("User Already Exist, Please choose a Different Username.");
    } else {
        const saltRounds = 10;
        const hashPassword = await bcrypt.hash(data.password, saltRounds);

        data.password = hashPassword;

        const userdata = await collection.insertMany([data]);
        res.redirect("/admin");
    }
});

app.post("/admin/edit", async (req, res) => {
    const { id, username, password, emailId } = req.body;
    const saltRounds = 10;
    const hashPassword = await bcrypt.hash(password, saltRounds);

    await collection.findByIdAndUpdate(id, { name: username, password: hashPassword, emailId: emailId });
    res.redirect("/admin");
});

app.post("/admin/delete", async (req, res) => {
    const { id } = req.body;
    await collection.findByIdAndDelete(id);
    res.redirect("/admin");
});

app.get("/admin/search", async (req, res) => {
    const searchQuery = req.query.username || "";
    const users = await collection.find({ name: new RegExp(searchQuery, 'i') });
    res.render("adminDashboard", { users, searchQuery });
});

app.get("/createuser", (req, res) => {
    res.render("createuser");
});
>>>>>>> ec867de18a80236e2b318efa1eba9ec97ba5b1d7

    // Protected admin routes
    app.get("/createuser", checkAdmin, (req, res) => res.render("createuser"));

    // Admin create user
    app.post("/admin/create", checkAdmin, async (req, res) => {
        const { username, password } = req.body;
        try {
            const existingUser = await collection.findOne({ name: username });
            if (existingUser) return res.status(400).send("User already exists");
            const hashedPassword = await bcrypt.hash(password, 10);
            await collection.insertOne({ name: username, password: hashedPassword, bio: '', profilePicture: '' });
            res.redirect('/admin/dashboard');
        } catch (err) {
            res.status(500).send("Error creating user");
        }
    });

    // Admin edit user
    app.post("/admin/edit", checkAdmin, async (req, res) => {
        const { id, username, password } = req.body;
        try {
            const update = { name: username };
            if (password) {
                update.password = await bcrypt.hash(password, 10);
            }
            await collection.updateOne({ _id: require('mongodb').ObjectId(id) }, { $set: update });
            res.redirect('/admin/dashboard');
        } catch (err) {
            res.status(500).send("Error updating user");
        }
    });

    // Admin delete user
    app.post("/admin/delete", checkAdmin, async (req, res) => {
        const { id } = req.body;
        try {
            await collection.deleteOne({ _id: require('mongodb').ObjectId(id) });
            res.redirect('/admin/dashboard');
        } catch (err) {
            res.status(500).send("Error deleting user");
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

    // Start the server
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
    });
}

startServer();
