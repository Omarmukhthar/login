const express = require("express");
const path = require("path");
const bcrypt = require("bcrypt");
const collection = require("./config");

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.set('view engine', 'ejs');

app.use(express.static("public"));


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

const port = 5000;
app.listen(port, () => {
    console.log(`Server running on port: ${port}`);
});
