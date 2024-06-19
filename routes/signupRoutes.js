const express = require('express');
const router = express.Router();
// const userController = require('../controllers/usercontroller');
const signupController = require('../controllers/signupController')
const authMiddleware = require('../middleware/authMiddleware')

router.post('/signup' , signupController.signup) ; 
router.put("/verify/:mail" , signupController.verifyEmail)
router.post('/login' , signupController.loginUser) ; 
router.post('/verify-otp' , signupController.verifyOpt ) ; 
router.post('/add-website' ,authMiddleware, signupController.addwebsite) ; 

module.exports = router;
