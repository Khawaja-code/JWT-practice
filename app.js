  require("dotenv").config();
const express = require('express'); 

const app = express();
const mongoose = require('mongoose');
const dbUrl = process.env.DB_URL
const User = require('./models/users.js')
const bcrypt = require('bcrypt')
const jwt = require("jsonwebtoken");
const JWT_SECRET =process.env.JWT_SECRET
const cookieParser = require('cookie-parser');
app.use(express.json())
app.use(cookieParser())

const authMiddleware= (req,res,next)=>{
    try{
        const token = req.cookies.token
        if(!token){
            return res.status(401).json({
            message:'unauthorized'
        })
        }
        const decoded = jwt.verify(token,JWT_SECRET)
         req.user = decoded
         next() 
    } catch(e){
       return res.status(401).json({
            message:'unauthorized'
        })
    }

}
async function connectDB() {
    await mongoose.connect(dbUrl)
}
connectDB().then(() => console.log("Connected to MongoDB")).catch(err => console.log(err));

app.post('/api/auth/register',async(req,res)=>{
    const{email,name,password} = req.body
    if(!name || !email || !password){
        return res.status(400).json({
            message:'All fields are required'
        })
    }
    const existedUser =await User.findOne({email})
    if(existedUser){
       return res.status(409).json({message:"user already existed",})
    }
    
        let hashPass = await bcrypt.hash(password,10)
        const newUser = new User({email,name,password:hashPass})
        await newUser.save()
        res.status(201).json({message:'user created'})
    
})

app.post('/api/auth/login',async(req,res)=>{
    const{email, password} = req.body
     if( !email || !password){
        return res.status(400).json({
            message:'All fields are required'
        })
    }
   const existingUser = await User.findOne({ email });

if (!existingUser) {
    return res.status(401).json({
        message: "Invalid email or password"
    });
}

const isMatch = await bcrypt.compare(
    password,
    existingUser.password
);

if (!isMatch) {
    return res.status(401).json({
        message: "Invalid email or password"
    });
}
const payload = {
    userId:existingUser._id
}
const token = jwt.sign(payload,JWT_SECRET,{
    expiresIn:"1h"
})
res.cookie("token", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 1000 * 60 * 60 // 1 hour
});
return res.status(200).json({
    message: "User logged in",
});
})
app.get('/profile',authMiddleware,async(req,res)=>{
    const user = await User.findById(req.user.userId).select('-password')
    res.status(200).json({
        user
    })
})
app.listen(process.env.PORT, () => {
    console.log("Server is running");
})