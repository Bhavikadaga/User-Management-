const mongoose = require('mongoose');

const sessionSchema = new mongoose.Schema({
    sessionId: {type: String},
    device: {type: String},
    ip: {type: String},
    createdAt: {type: Date, default: Date.now},
    lastActive: {type: Date, default: Date.now},
}, {_id: false});

const userSchema = new mongoose.Schema({
    name: {type: String, required: true},
    email: {type: String, required: true, unique: true, lowercase: true},
    password: {type: String},

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

    role: {
        type: String,
        enum: ['user', 'admin'],
        default: 'user'
    },

    isEmailVerified: {type: Boolean, default: false},
    emailVerifyToken: {type: String},
    emailVerifyExpires: {type: Date},

    passwordResetToken: {type: String},
    passwordResetExpires: {type: Date},

    lastLogin: {type: Date},
    activeSessions: [sessionSchema],

}, {timestamps: true});

userSchema.methods.toJSON = function () {
    const obj = this.toObject(); //plain json data
    delete obj.password;
    delete obj.emailVerifyToken;
    delete obj.passwordResetToken;
    return obj; 
}

module.exports = mongoose.model('User', userSchema);