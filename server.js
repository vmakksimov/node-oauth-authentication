const fs = require('fs');
const https = require('https');
const express = require('express');
const helmet = require('helmet');
const path = require('path');
const passport = require('passport')
const cookieSession = require('cookie-session');
const { Strategy} = require('passport-google-oauth20');

require('dotenv').config();

const config = {
    CLIENT_ID : process.env.CLIENT_ID,
    CLIENT_SECRET: process.env.CLIENT_SECRET,
    COOKIE_KEY_1: process.env.COOKIE_KEY_1,
    COOKIE_KEY_2: process.env.COOKIE_KEY_2
}

const AUTH_OPTIONS = {
    callbackURL : '/auth/google/callback',
    clientID: config.CLIENT_ID,
    clientSecret: config.CLIENT_SECRET
}

function verifyCallBack(accessToken, refreshToken, profile, done){
    console.log('user profile', profile) 
    done(null, profile)
}

passport.use(new Strategy(AUTH_OPTIONS, verifyCallBack))

//save the session to the cookie
passport.serializeUser((user, done) => {
    done(null, user.id)
})

//getting user from the cookie
passport.deserializeUser((obj, done) => {
    // User.findById(obj).then(user => {
    //     done(null, user)
    // })
    done(null, obj)
})
const app = express();
app.use(helmet());
app.use(cookieSession({
    name: 'session',
    maxAge: 24 * 60 * 60 * 1000,
    keys: [config.COOKIE_KEY_1, config.COOKIE_KEY_2]

}))
app.use(passport.initialize());
app.use(passport.session());

function checkLoggedIn(req, res, next){
    const IsLogged = req.isAuthenticated() && req.user;
    if (!IsLogged){
        return res.status(400).json({error: "You must be logged in"})
    }

    next();

}

app.get('/secret', checkLoggedIn, (req, res) => {
    return res.send('This is secret 42!')
})

app.get('/auth/google', passport.authenticate('google', {
    scope: ['email'],
}))

app.get('/auth/google/callback', passport.authenticate('google', {
    failureRedirect: '/failure',
    successRedirec: '/',
    session: true,
}), (req, res) => {
    console.log('Google we are in!')
    return res.status(200).redirect('/')
})

app.get('/failure', (req, res) => {
    return req.send('Failed to log in!')
})

app.get('/auth/logout', (req, res)=> {
    console.log("logout user:", req.user)
    req.logout();
    return res.redirect('/')
})

app.get('/', (req, res) => {
    return res.sendFile(path.join(__dirname, 'public', 'index.html'))
})

const server = https.createServer({
    cert: fs.readFileSync('cert.pem'),
    key: fs.readFileSync('key.pem')
}, app)

server.listen(3000, () => {
    console.log('Listening on port 3000...')
})