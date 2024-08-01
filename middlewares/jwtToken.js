import jwt from 'jsonwebtoken';

export const authenticateToken = (req,res,next) => {
    const authHeader = req.headers['authorization'] // get the authorization header out.
    const token = authHeader && authHeader.split(' ')[1] // separating "Bearer and Token" and taking only Token by using [1].

    if (!token) return res.status(401).json({message:'Authorization failed. No token found.'}) // Returning if no token found.
    
    // Now if token is there we verify it.
    jwt.verify(token, process.env.ACCESS_TOKEN_KEY, (err,user)=>{
        
        if(err) return res.status(403).json({message: 'user doesnt have access to view this resource. As the token is no more valid'}) // This is when verification fails of token.
        req.user = user; // This is when everything is ok so now we can attach user info came from token to req object of api route function.
        next(); // Calling next as it is a middleware.
    })
}