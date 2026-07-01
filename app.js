  require("dotenv").config();
  class ExpressError extends Error {
   constructor(status,message){
    super(message)
    this.status=status
   }
}
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

// const wrapAsync = (fn)=>{
//   return async(req,res,next)=>{
//     try{
//     await fn(req,res,next)}
//     catch(err){next(err)}
//   }
// } 
// it is simpler version

const wrapAsync = (fn)=>{
    return (req,res,next)=>{
        fn(req,res,next).catch(next)
    }
}
// this is shorter one


const authMiddleware= (req,res,next)=>{
    try{
        const token = req.cookies.token
        if(!token){
            throw new ExpressError(401,'Unauthorized')
        }
        const decoded = jwt.verify(token,JWT_SECRET)
         req.user = decoded
         next() 
    } catch(e){
       next(e)
    }

}
async function connectDB() {
    await mongoose.connect(dbUrl)
}
connectDB().then(() => console.log("Connected to MongoDB")).catch(err => console.log(err));

app.post('/api/auth/register',wrapAsync(async(req,res)=>{
    const{email,name,password} = req.body
    if(!name || !email || !password){
       throw new ExpressError(400,'All details required')
        
    }
    const existedUser =await User.findOne({email})
    if(existedUser){
       throw new ExpressError(409,'User already existed')
    }
    
        let hashPass = await bcrypt.hash(password,10)
        const newUser = new User({email,name,password:hashPass})
        await newUser.save()
        res.status(201).json({message:'user created'})
    
}))

app.post('/api/auth/login',wrapAsync(async(req,res)=>{
    const{email, password} = req.body
     if( !email || !password){
               throw new ExpressError(400,'All details required')

    }
   const existingUser = await User.findOne({ email });

if (!existingUser) {
    throw new ExpressError(401,'Invaid email or password')
}

const isMatch = await bcrypt.compare(
    password,
    existingUser.password
);

if (!isMatch) {
     throw new ExpressError(401,'Invaid email or password')

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
})
}))
app.get('/profile',authMiddleware,wrapAsync(async(req,res)=>{
    const user = await User.findById(req.user.userId).select('-password')
    res.status(200).json({
        user
    })
}))
app.use((err,req,res,next)=>{
    const {status=500, message="Something went wrong"} = err
    res.status(status).json({message})
})
app.listen(process.env.PORT, () => {
    console.log("Server is running");
})