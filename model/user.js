const mongoose = require('mongoose');
const { date, lowercase } = require('zod');
const { da } = require('zod/locales');
const { required } = require('zod/mini');

const sessionSchema = new mongoose.Schema({
    sessionId: {type: String},
    device: {type: String},
    ip: {type: String},
    createdAt: {type: Date, default: Date.now},
    lastActive: {type: Date, default: Date.now},
}, {_id: false});

const userSchmea = new mongoose.Schema({
    name: {type: String, require: true},
    email: {type: String, required: true, unique: true, lowercase: true},
    password: {type: String},

    // OAuth
    providers: {
        google: {
            id: {type: String},
            picture: {type: String},
        },
        github: {
            id: {type: String},
            picture: {type: String},
        }
    },

    // Role base access
    role: {
        type: String,
        enum: ['user', 'admin'],
        default: 'user'
    },

    // email verificationn
    isEmailVerified: {type: Boolean, default: false},
    emailVerifyToken: {type: String},
    emailVerifyExpires: {type: Date},

    passwordResetToken: {type: String},
    passwordResetExpires: {type: String},

    lastLogin: {type: String},
    activeSessions: [sessionSchema],

}, {timestamps: true});

userSchmea.methods.toJSON = function () {
    const obj = this.toObject(); //plain json data
    delete obj.password;
    delete obj.emailVerifyToken;
    delete obj.passwordResetToken;
    return obj; 
}