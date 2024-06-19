const { configDotenv } = require('dotenv');
const jwt = require('jsonwebtoken');
const { decode } = require('punycode');

const JWT_SECRET = process.env.JWT_SECRET || "your_secret_key" 

const authMiddleware = (req, res, next) => {
    const token = req.header('Authorization')?.split(' ')[1];
    console.log("token is " , token)
    if (!token) {
        return res.status(401).json({ message: 'Access denied. No token provided.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded; 
        
        console.log("decoded value is" , decoded)
        next();
    } catch (error) {
        res.status(400).json({ message: 'Invalid token.' });
    }
};

module.exports = authMiddleware;
