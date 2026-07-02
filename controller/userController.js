const User = require('../model/user.js');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { sendVerificationEmail, sendPasswordResetEmail } = require('../config/email.js');
const { signupSchema, loginSchema } = require('../validators/authValidator.js');

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

        // FIX: generate verify token BEFORE returning response
        const rawToken = crypto.randomBytes(32).toString('hex');
        const hashedToken = crypto.createHash('sha256').update(rawToken).digest('hex');

        await User.findByIdAndUpdate(user._id, {
            emailVerifyToken:   hashedToken,
            emailVerifyExpires: Date.now() + 24 * 60 * 60 * 1000
        });

        await sendVerificationEmail(user.email, rawToken);

        const token = await createSessionAndToken(user, req);
        res.cookie('token', token, cookieOptions);

        return res.status(201).json({
            message: 'User created successfully. Please verify your email.',
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
    } catch (err) {
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
        console.error('OAuth callback error:', err);
        res.redirect('/');
    }
};

const sendVerifyEmail = async (req, res) => {
    try {
        const token = req.cookies?.token;
        if (!token) return res.status(401).json({ message: 'Not logged in' });

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.id);

        if (!user) return res.status(404).json({ message: 'User not found' });
        if (user.isEmailVerified) {
            return res.status(400).json({ message: 'Email already verified' });
        }

        const rawToken = crypto.randomBytes(32).toString('hex');  // FIX: no typo
        const hashedToken = crypto
            .createHash('sha256')                                  // FIX: was .create()
            .update(rawToken)
            .digest('hex');

        user.emailVerifyToken   = hashedToken;
        user.emailVerifyExpires = Date.now() + 24 * 60 * 60 * 1000; // FIX: was useremailverifyExpires
        await user.save();

        await sendVerificationEmail(user.email, rawToken);
        return res.status(200).json({ message: 'Verification email sent' });

    } catch (err) {
        console.error('Send verify email error:', err);
        return res.status(500).json({ message: 'Internal server error' });
    }
};

const verifyEmail = async (req, res) => {                          // FIX: was missing entirely
    try {
        const { token } = req.query;
        if (!token) return res.status(400).json({ message: 'No token provided' });

        const hashedToken = crypto
            .createHash('sha256')
            .update(token)
            .digest('hex');

        const user = await User.findOne({
            emailVerifyToken:   hashedToken,
            emailVerifyExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ message: 'Invalid or expired token' });
        }

        user.isEmailVerified    = true;
        user.emailVerifyToken   = undefined;
        user.emailVerifyExpires = undefined;
        await user.save();

        return res.status(200).json({ message: 'Email verified successfully' });

    } catch (err) {
        console.error('Verify email error:', err);
        return res.status(500).json({ message: 'Internal server error' });
    }
};

const forgotPassword = async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ message: 'Email is required' });

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(200).json({ message: 'If that email exists, a reset link has been sent' });
        }
        if (!user.password) {
            return res.status(400).json({ message: 'This account uses Google or GitHub login' });
        }

        const rawToken = crypto.randomBytes(32).toString('hex');
        const hashedToken = crypto.createHash('sha256').update(rawToken).digest('hex');

        user.passwordResetToken   = hashedToken;
        user.passwordResetExpires = Date.now() + 60 * 60 * 1000;
        await user.save();

        await sendPasswordResetEmail(user.email, rawToken);
        return res.status(200).json({ message: 'If that email exists, a reset link has been sent' });

    } catch (err) {
        console.error('Forgot password error:', err);
        return res.status(500).json({ message: 'Internal server error' });
    }
};

const resetPassword = async (req, res) => {
    try {
        const { token } = req.query;
        const { password, confirmedPassword } = req.body;

        if (!token) return res.status(400).json({ message: 'No token provided' });
        if (password !== confirmedPassword) {
            return res.status(400).json({ message: "Passwords don't match" });
        }

        const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

        const user = await User.findOne({
            passwordResetToken:   hashedToken,
            passwordResetExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ message: 'Invalid or expired token' });
        }

        const result = signupSchema.shape.password.safeParse(password);
        if (!result.success) {
            return res.status(400).json({ errors: result.error.errors });
        }

        user.password             = await bcrypt.hash(password, 10);
        user.passwordResetToken   = undefined;
        user.passwordResetExpires = undefined;
        user.activeSessions       = [];
        await user.save();

        res.clearCookie('token', cookieOptions);
        return res.status(200).json({ message: 'Password reset successfully. Please log in again.' });

    } catch (err) {
        console.error('Reset password error:', err);
        return res.status(500).json({ message: 'Internal server error' });
    }
};

module.exports = {
    signup,
    login,
    logout,
    oauthCallback,
    sendVerifyEmail,
    verifyEmail,
    forgotPassword,
    resetPassword
};