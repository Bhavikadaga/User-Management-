const express = require('express');
const app = express();
const mongoose = require('mongoose');
const authRoutes = require('./routes/auth.js');
require('dotenv').config();
const cors = require('cors');

app.use(cors());
app.use(express.json());

app.use('/auth', authRoutes);
app.get('/', (req, res) => res.send("Heyy"));

const port = process.env.PORT || 5000;

mongoose.connect(process.env.MONGODB_URI)
.then(() => console.log("MongoDB connected"))
.catch(err => console.log("Error detected", err));

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});