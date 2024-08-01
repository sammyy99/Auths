import express from 'express';
import cors from 'cors';
import 'dotenv/config';
import jwt from 'jsonwebtoken';
import { authenticateToken } from './middlewares/jwtToken.js';

const app = express();
const PORT = 5000;

const userTable = [
    {userId : 1, username : 'sam', password: 'sam'},
    {userId : 2, username : 'zack', password: 'zack'},
    {userId : 3, username : 'cody', password: 'cody'},
]
let refreshTokens = []; // Taking it as local DB

app.use(express.urlencoded({extended:true}));
app.use(express.json());
app.use(cors());

app.get('/api',(req,res)=>{
    res.status(200).json({message:'Welcome to API'})
})

app.post('/login',(req,res)=>{
   // Authentication by DB
   const {username, password} = req.body;
   const user = userTable.find((u)=> u.username === username && u.password === password)
   
   if (!user) return res.status(401).json({message:'Invalid credentials'})
   
   // now user checked by DB if its valid we can create access token and refresh token

   const accessToken = jwt.sign({username : user.username}, process.env.ACCESS_TOKEN_KEY, {expiresIn:'30s'})
   const refreshToken = jwt.sign({username : user.username}, process.env.REFRESH_TOKEN_KEY)

   res.status(200).json({message:'Token generated / Logged in',accessToken,refreshToken})
   
})

app.post('/token',(req,res)=>{
    const {token} = req.body;

    if(!token) return res.status(401).json({message:'No token. Authentication failed.'}); // If no token straight kick away
    //if(!refreshTokens.includes(token)) return res.status(403).json({message:'No refresh token found.'}); // Server will see if there is any refresh token for this user
    
    // Now if there is any refresh token available we have to verify it.
    jwt.verify(token, process.env.REFRESH_TOKEN_KEY,(err,user)=>{
        if(err) return res.status(403).json({message:'You are not authorized to access this resourse'})
        
        // Generate a new access token with the user information
        const accessToken = jwt.sign({username: user.username},process.env.ACCESS_TOKEN_KEY,{expiresIn:'30s'})

        // Respond with the new access token
        res.json({ accessToken });
    })
})

app.get('/home', authenticateToken, (req,res)=>{
    res.status(200).json({message : 'This is protected route which is accessed with token.', user: req.user})
})

app.listen(PORT,()=>{console.log(`Server started at ${PORT}.`)})
