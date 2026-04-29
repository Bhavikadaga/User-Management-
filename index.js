const express = require('express');
const app = express();
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const authRoutes = require('./routes/auth.js');
const cors = require('cors');
require('dotenv').config();


app.use(cors({
    origin: process.env.CLIENT_URL || 'https://localhost:3000',
    credentials: true
}));
app.use(express.json());

// sessions
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninstalized: false,
    store: MongoStore.create({mongourl: process.env.MONGODB_URI}),
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 14*24*60*60*1000
    }
}));

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