import express from 'express';
import { register, login, logout, sendVerifyOtp, verifyEmail, isAuthenticated, sendResetOtp, resetPassword } from '../controllers/authController.js';  // Import the required functions
import userAuth from '../middleware/userAuth.js';  // Import the middleware

const authRouter = express.Router();

// Define routes with middleware and controller functions
authRouter.post('/register', register);
authRouter.post('/login', login);
authRouter.post('/logout', logout);
authRouter.post('/send-verify-otp', userAuth, sendVerifyOtp);  // Use the middleware and controller
authRouter.post('/verify-account', userAuth, verifyEmail);  // Use the middleware and controller
authRouter.get('/is-auth', userAuth, isAuthenticated);  // Use the middleware and controller
authRouter.post('/send-reset-otp',sendResetOtp);  // Use the middleware and controller
authRouter.post('/reset-password',resetPassword);  // Use the middleware and controller

export default authRouter;
