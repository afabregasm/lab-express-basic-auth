const router = require("express").Router();
const mongoose = require("mongoose");
const bcryptjs = require('bcryptjs');
const saltRounds = 10;

const User = require('../models/User.model');

const { isLoggedIn, isLoggedOut } = require("../middleware/route-guard.js");

router.get('/signup', isLoggedOut, (req, res) => {
    res.render('../views/auth/signup.hbs')
});

router.post('/signup', (req, res, next) => {
    const { username, password } = req.body;
    if (!username || !password) {
        res.render("../views/auth/signup.hbs", {
            errorMessage: "All fields are mandatory. Please provide your username and password."
        });
        return;
    }
    bcryptjs
    .genSalt(saltRounds)
    .then(salt => {
        return bcryptjs.hash(password, salt)
    })
    .then(hashedPassword => {
        return User.create({
            username,
            password: hashedPassword
        })
    })
    .then((userFromDB) => {
        res.redirect('/profile')
    })
    .catch((error) => {
        if (error instanceof mongoose.Error.ValidationError) {
          res.status(500).render("../views/auth/signup.hbs", { errorMessage: error.message });
        } else if (error.code === 11000) {
          res.status(500).render("../views/auth/signup.hbs", {
            errorMessage: "Username is already used."
          });
        } else {
          next(error);
        }
      });
});

router.get('/login', (req, res) => {
    res.render('../views/auth/login.hbs')
});

router.post("/login", (req, res, next) => {
    const { username, password } = req.body;
    if (username === "" || password === "") {
        res.render('../views/auth/login.hbs', {
            errorMessage: "Please enter both, username and password to login."
        });
        return;
    }
    User.findOne({ username })
    .then((user) => {
        console.log(user)
        if (!user) {
            res.render('../views/auth/login.hbs', { errorMessage: "User is not registered. Try with other username." });
        return;
        } else if (bcryptjs.compareSync(password, user.password)) {
            req.session.currentUser = user;
            res.redirect("/profile");
        } else {
            res.render("../views/auth/login.hbs", { errorMessage: "Incorrect password." });
        }
    })
    .catch((error) => {
        next(error)
    })
})

router.get('/profile', isLoggedIn, (req, res) => {
    res.render('../views/users/profile.hbs', { userInSession: req.session.currentUser })
});

module.exports = router;