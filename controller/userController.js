const User = require('../model/user.js');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { signupSchema, loginSchema } = require('../validators/authValidator.js');
// FIX: removed wrong passport import — doesn't belong here

const cookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000
};

const createSessionAndToken = async (user, req) => {
    const sessionId = crypto.randomBytes(32).toString('hex');
    const token = jwt.sign(
        { id: user._id, email: user.email, role: user.role, sessionId },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
    );
    await User.findByIdAndUpdate(user._id, {
        $push: {
            activeSessions: {
                sessionId,
                device:     req.headers['user-agent'] || 'Unknown',
                ip:         req.ip,
                createdAt:  new Date(),
                lastActive: new Date()
            }
        },
        lastLogin: new Date()
    });
    return token;
};

const signup = async (req, res) => {
    try {
        const result = signupSchema.safeParse(req.body);
        if (!result.success) {
            return res.status(400).json({ errors: result.error.errors });
        }

        const { name, email, password } = result.data;
        const existUser = await User.findOne({ email });
        if (existUser) return res.status(400).json({ message: 'User already exists' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await User.create({ name, email, password: hashedPassword });

        const token = await createSessionAndToken(user, req);
        res.cookie('token', token, cookieOptions);

        return res.status(201).json({
            message: 'User created successfully',
            user: { id: user._id, name: user.name, email: user.email, role: user.role }
        });
    } catch (err) {
        console.error('Signup error', err);
        return res.status(500).json({ message: 'Internal server error' });
    }
};

const login = async (req, res) => {
    try {
        const result = loginSchema.safeParse(req.body);
        if (!result.success) {
            return res.status(400).json({ errors: result.error.errors });
        }

        const { email, password } = result.data;
        const existUser = await User.findOne({ email });
        if (!existUser) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }
        if (!existUser.password) {
            return res.status(400).json({ message: 'This account uses Google or GitHub login' });
        }

        const isMatch = await bcrypt.compare(password, existUser.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }

        const token = await createSessionAndToken(existUser, req);
        res.cookie('token', token, cookieOptions);

        return res.status(200).json({
            message: 'Login successful',
            user: { id: existUser._id, name: existUser.name, email: existUser.email, role: existUser.role }
        });
    } catch (err) {
        console.error('Login error:', err);
        return res.status(500).json({ message: 'Internal server error' });
    }
};

const logout = async (req, res) => {
    try {
        const token = req.cookies?.token;
        if (token) {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            await User.findByIdAndUpdate(decoded.id, {
                $pull: { activeSessions: { sessionId: decoded.sessionId } }
            });
        }
    } catch (err) {                                        // FIX: was 'error'
        console.error('Logout error:', err);
    } finally {
        res.clearCookie('token', cookieOptions);
        return res.status(200).json({ message: 'Logged out successfully' });
    }
};

const oauthCallback = async (req, res) => {
    try {
        const token = await createSessionAndToken(req.user, req);
        res.cookie('token', token, cookieOptions);
        res.redirect(process.env.CLIENT_URL + '/dashboard');
    } catch (err) {
        console.error('OAuth callback error:', err);       // FIX: was console.err
        res.redirect('/');
    }
};

module.exports = { signup, login, logout, oauthCallback };