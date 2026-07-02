const jwt = require('jsonwebtoken');
const User = require('../model/user.js');

module.exports = async function isAuthenticated(req, res, next){
    try{
        const token = req.cookies?.token;
        if(!token){
            return res.status(401).json({message: 'Not logged in'});
        }
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        const user = await User.findById(decoded.id);
        if(!user){
            return res.status(401).json({message: 'User no longer exists'});
        }
        const sessionExists = user.activeSessions
            .some(s => s.sessionId === decoded.sessionId);
        if(!sessionExists){
            return res.status(401).json({message: 'Session expired. Please log in again'});
        } 
        req.user = user;
        next();   
    }catch(err){
        return res.status(401).json({message: 'Invalid or expired token'})
    }
};