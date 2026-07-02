const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

const sendVerificationEmail = async(email, token) =>{
    const verifyURL = `http://localhost:5000/auth/verify-email?token=${token}`;
    await transporter.sendMail({
        from: `"User Management" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: 'Verfy your email',
        html: `
            <h2>Verfy your email</h2>
            <p>Click the link below to verify you email. This link expires in 24 hours.</p>
            <a href="${verifyURL}">${verifyURL}</a>
        `
    });
};

const sendPasswordResetEmail = async (email, token) =>{
    const resetURL = `http://localhost:5000/auth/reset-password?token=${token}`;
    await transporter.sendMail({
        from: `"User Management" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: 'Reset your password',
        html: `
            <h2>Reset you password</h2>
            <p>Click the link below to reset your password. This link expires in 1 hour.</p>
            <a href="${resetURL}">${resetURL}</a>
            <p>If you didn't request this, ignore this email.</p>
        `
    });
};

module.exports = { sendVerificationEmail, sendPasswordResetEmail };