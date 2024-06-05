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
app.get("/login", (req, res) => {
    res.render("login"); 
});

app.get("/signup", (req, res) => {
    res.render("Signup");
});

app.post("/signup", async (req, res) => {
    const data = {
        name: req.body.username,
        password: req.body.password
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
        const check = await collection.findOne({ name: req.body.username });
        if (!check) {
            res.send("User not found");
        } else {
            const isPasswordMatch = await bcrypt.compare(req.body.password, check.password);
            if (isPasswordMatch) {
                res.render("home");
            } else {
                res.send("Wrong password"); 
            }
        }
    } catch (error) {
        res.send("Wrong Details");
    }
});
app.post("/logout", (req, res) => {
    res.redirect("/login"); 
});

const port = 5000;
app.listen(port, () => {
    console.log(`Server running on port: ${port}`);
});
