const express = require('express');
const app = express();
const mongoose = require('mongoose');
const session = require('express-session');  //temporary server-side sessions
const MongoStore = require('connect-mongo');
const cookieParser = require('cookie-parser');
const passport = require('passport');
const authRoutes = require('./routes/auth.js');
const cors = require('cors');
require('dotenv').config();
console.log('Google ID loaded:', !!process.env.GOOGLE_CLIENT_ID);

app.use(cors({
    origin: process.env.CLIENT_URL || 'http://localhost:3000',
    credentials: true
}));
app.use(express.json());
app.use(cookieParser());  

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGODB_URI
    }),
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 14*24*60*60*1000
    }
}));

require('./config/passport.js');
app.use(passport.initialize());
app.use(passport.session());

app.use('/auth', authRoutes);
app.get('/', (req, res) => res.send("Auth server running"));

const port = process.env.PORT || 5000;

mongoose.connect(process.env.MONGODB_URI)
.then(() => {
    console.log("MongoDB connected");
    app.listen(port, () => {
        console.log(`Server running at http://localhost:${port}`);
    });
})
.catch(err => console.log("Error detected", err));