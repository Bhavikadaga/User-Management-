const express = require('express');
const router = express.Router();
const passport = require('passport');
const { signup, login, logout, oauthCallback } = require('../controller/userController.js');

router.post('/signup', signup);
router.post('/login', login);
router.post('/logout', logout);

router.get('/google', 
    passport.authenticate('google', {scope: ['openid', 'profile', 'email']})
);
router.get('/google/callback',
    passport.authenticate('google', {failureRedirect: '/'}),
    oauthCallback
);
router.get('/github', 
    passport.authenticate('github', {scope: ['user:email']})
);
router.get('/github/callback',
    passport.authenticate('github', {failureRedirect: '/'}),
    oauthCallback
)

module.exports = router;