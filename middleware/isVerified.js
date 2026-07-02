module.exports = function isVerified(req, res, next) {
    if (req.user && !req.user.isEmailVerified) {
        return res.status(403).json({
            message: 'Please verify your email before continuing'
        });
    }
    next();
};