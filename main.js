if (process.env.NODE_ENV != "production") {
    const dotenv = await import("dotenv");
    dotenv.config();
}

import Express from "express";
import ExpressFlash from "express-flash";
import ExpressSession from "express-session";
import Passport from "passport";
import MethodOverride from "method-override";

const App = Express();
App.set("view engine", "ejs"); // Set view engine to ejs to allow for dynamic pages

// Enable parsing of request body using json and urlencoded
App.use(Express.urlencoded({ extended: false })); // For parsing application/x-www-form-urlencoded
App.use(Express.json()); // For parsing application/json

App.use(ExpressFlash()); // Flash messages aka temporary messages

// Allow for session management
App.use(ExpressSession({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false}));

// Allow Express to use Passport and Passport sessions
App.use(Passport.initialize());
App.use(Passport.session());

// Allow for PUT and DELETE requests
App.use(MethodOverride("_method"));

import bcrypt from "bcrypt";
const SaltRounds = 10;

import FS from "fs";

var UsersDB = []; // Array to store the users loaded from the JSON file

// Handle user authentication and validation
async function Authenticate(username, password, done) {
    // Attempt to get user from username or email
    const User = UsersDB.Users.find(u => u.username.toLowerCase() == username.toLowerCase() || u.email.toLowerCase() == username.toLowerCase());
    if (!User) {
        return done(null, false, { message: "No user found" });
    }

    try {
        if (!await bcrypt.compare(password, User.password)) {
            return done(null, false, { message: "Invalid password" });
        }

        return done(null, User);
    } catch (e) {
        return done(e);
    }
}

function FindByID(id) {
    return UsersDB.Users.find(u => u.id == id);
}

// Fully initialize passport
import { Initialize } from "./passport-config.js";
Initialize(Passport, Authenticate, FindByID);

// Clear console used for debugging
process.stdout.write("\u001b[2J\u001b[0;0H");
console.log("Cleared console");

// This is temporary, in a real app you would use a database
// function to refresh users from file
function RefreshUsers() {
    // Read from file
    const data = FS.readFileSync("users.json");
    UsersDB = JSON.parse(data);
}

// function to save users to file
function SaveUsers() {
    // Write to file
    FS.writeFileSync("users.json", JSON.stringify(UsersDB));
}
// End of temporary

// Views AKA pages

// Home page
App.get("/", CheckAuth, (req, res) => {
    res.render("index.ejs", { username: req.user.username });
});

// Login page
App.get("/login", CheckNotAuth, (req, res) => {
    res.render("login.ejs");
});

// Handle login post requests
App.post("/login", CheckNotAuth, Passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
    failureFlash: true
}));

// Register page
App.get("/register", CheckNotAuth, (req, res) => {
    res.render("register.ejs");
});

// Handle register post requests
App.post("/register",  CheckNotAuth, async (req, res) => {
    const User = {
        id: UsersDB.Users.length,
        username: req.body.username,
        email: req.body.email.toLowerCase(),
        password: req.body.password
    };

    // Validation
    if (User.username == "" || User.email == "" || User.password == "") {
        res.status(400).json({ message: "Invalid data" });
        return;
    }

    try {
        const HashedPassword = await bcrypt.hash(User.password, SaltRounds);
        User.password = HashedPassword;
    } catch (e) {
        console.log(e);
        res.status(500).json({ message: "Internal server error" });
        return;
    }

    // Check if email is already in use
    const bEmailInUse = UsersDB.Users.find(u => u.email == User.email);
    if (bEmailInUse) {
        res.status(400).json({ message: "Email already in use" });
        return;
    }

    // Check if username is already in use
    const bUsernameInUse = UsersDB.Users.find(u => u.username == User.username);
    if (bUsernameInUse) {
        res.status(400).json({ message: "Username already in use" });
        return;
    }

    UsersDB.Users.push(User);
    SaveUsers();
    RefreshUsers();

    res.status(201).send();
});

// Logout
App.delete("/logout", CheckAuth, (req, res, next) => {
    req.logOut((err) => {
        if (err) {return next(err); }

        res.redirect("/");
    });
});

// Middleware to check if user is authenticated
function CheckAuth(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }

    res.redirect("/login");
}

function CheckNotAuth(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect("/");
    }

    next();
}

App.listen(process.argv[2] || 8080);
RefreshUsers(); // Load users from file on start

console.log(`Server started on port ${process.argv[2] || 8080}`);