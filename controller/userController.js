const User = require('../model/user.js');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { signupSchema, loginSchema } = require('../validators/authValidator.js');

const signup = async(req, res) => {
    try{
        const result = signupSchema.safeParse(req.body);
        if(!result.success){
            return res.status(400).json({ errors: result.error.errors });
        }

        const {name, email, password} = result.data;
        const existUser = await User.findOne({email});

        if(existUser) return res.status(400).json({message: "User already exists"});

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = await User.create({
            name, 
            email,
            password: hashedPassword
        });

        const token = jwt.sign(
            {id: user._id, email: user.email},
            process.env.JWT_SECRET,
            {expiresIn: '7d'}
        );

        res.status(201).json({
            message: "User created successfully",
            token,
            user:{
                id: user._id,
                name: user.name,
                email: user.email,
            }
        })
    }catch(err){
        res.status(500).json({message: err.message});
    }
}

const login = async(req, res) => {
    try{
        const result = loginSchema.safeParse(req.body);
        if(!result.success){
            return res.status(400).json({ errors: result.error.errors });
        }

        const {email, password} = result.data;
        const existUser = await User.findOne({email});

        if(!existUser){
           return res.status(400).json({message: "User not found"})
        }

        const isMatch = await bcrypt.compare(password, existUser.password);
        if(!isMatch){
            return res.status(400).json({message: "Invalid password"});
        }

        const token = jwt.sign(
            {id: existUser._id, email: existUser.email},
            process.env.JWT_SECRET,
            {expiresIn: '7d'}
        )
    
        res.status(200).json({
            message: 'Login successfully',
            token,
            user:{
                id: existUser._id,
                name: existUser.name,
                email: existUser.email
            }
        })
    }catch(error){
        console.log("Login error:", error);
        res.status(500).json({message: "Error in logging in", error})
    }
}

module.exports = {signup, login}