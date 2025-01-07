import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/userModel.js';  // Correct path
import transporter from '../config/nodemailer.js';
import { EMAIL_VERIFY_TEMPLATE, PASSWORD_RESET_TEMPLATE } from '../config/emailTemplates.js';

// Register Function
export const register = async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.json({ success: false, message: 'Missing Details' });
    }

    try {
        const existingUser = await userModel.findOne({ email });

        if (existingUser) {
            return res.json({ success: false, message: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new userModel({ name, email, password: hashedPassword });
        await user.save();

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in milliseconds
        });

        // Sending welcome email
        try {
            await transporter.sendMail({
                from: process.env.SENDER_EMAIL,
                to: email,
                subject: 'Welcome to Mityatc',
                text: `Hello ${name},\n\nWelcome to Mityatc! Your account has been successfully created with the email: ${email}.\n\nThank you for joining us!`,
            });
            console.log('Welcome email sent successfully.');
        } catch (emailError) {
            console.error('Error sending welcome email:', emailError);
        }

        return res.json({ success: true });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
};

// Login Function
export const login = async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.json({ success: false, message: 'Email and password are required' });
    }

    try {
        const user = await userModel.findOne({ email });

        if (!user) {
            return res.json({ success: false, message: 'Invalid Email' });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.json({ success: false, message: 'Invalid Password' });
        }

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in milliseconds
        });

        // Sending login notification email
        try {
            await transporter.sendMail({
                from: process.env.SENDER_EMAIL,
                to: email,
                subject: 'Welcome Back to Mityatc',
                text: `Hello,\n\nYou just logged into your account using ${email}. If this wasn't you, please contact our support team immediately.`,
            });
            console.log('Login notification email sent successfully.');
        } catch (emailError) {
            console.error('Error sending login notification email:', emailError);
        }

        return res.json({ success: true });
    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
};

// Logout Function
export const logout = async (req, res) => {
    try {
        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
        });

        return res.json({ success: true, message: 'Logged Out' });
    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
};

// Send Verification OTP
export const sendVerifyOtp = async (req, res) => {
    try {
        const { userId } = req.body;

        // Find user by userId (verify it properly if you're using authentication)
        const user = await userModel.findById(userId);

        if (!user) {
            return res.json({ success: false, message: 'User not found' });
        }

        if (user.isAccountVerified) {
            return res.json({ success: false, message: 'Account already verified' });
        }

        // Generate OTP
        const otp = String(Math.floor(100000 + Math.random() * 900000)); // 6 digit OTP

        // Save OTP in the user record
        user.verifyOtp = otp;
        user.verifyOtpExpireAt = Date.now() + 24 * 60 * 60 * 1000; // OTP expires in 24 hours
        await user.save();

        // Send OTP via email
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account verification OTP',
            //text: `Your OTP is ${otp}. Verify your account using this OTP.`,
            html: EMAIL_VERIFY_TEMPLATE.replace("{{otp}}", otp).replace("{{email}}", user.email)
        };

        await transporter.sendMail(mailOptions);

        res.json({ success: true, message: 'Verification OTP sent to email' });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
};

// Verify Email
export const verifyEmail = async (req, res) => {
    const { userId, otp } = req.body;

    if (!userId || !otp) {
        return res.json({ success: false, message: 'Missing Details' });
    }

    try {
        const user = await userModel.findById(userId);

        if (!user) {
            return res.json({ success: false, message: 'User not found' });
        }

        if (user.verifyOtp === '' || user.verifyOtp !== otp) {
            return res.json({ success: false, message: 'Invalid OTP' });
        }

        if (user.verifyOtpExpireAt < Date.now()) {
            return res.json({ success: false, message: 'OTP expired' });
        }

        // Mark the account as verified
        user.isAccountVerified = true;
        user.verifyOtp = ''; // Clear OTP
        user.verifyOtpExpireAt = 0; // Reset expiration
        await user.save();

        return res.json({ success: true, message: 'Email verified successfully' });
    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
};

// Check if user is authenticated
export const isAuthenticated = async (req, res)=>{
    try {
        return res.json({success:true});

    }catch (error){
        res.json({success: false, message: error.message});
    }

}

//Send password reset otp
export const sendResetOtp = async(req, res)=>{
    const {email} = req.body;

    if(!email){
        return res.json({success:false, message: 'Email is required'})
    }

    try {
        const user = await userModel.findOne({email});
        if(!user){
            return res.json({success:false, message: 'User not found.'});
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000)); // 6 digit OTP

        // Save OTP in the user record
        user.resetOtp = otp;
        user.resetOtpExpireAt = Date.now() + 15 * 60  * 1000; // OTP expires in 24 hours
        await user.save();

        // Send OTP via email
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account verification OTP',
            //text: `Your OTP for resetting your password is ${otp}. Use this OTP to proceed with resetting your password `,
            html: PASSWORD_RESET_TEMPLATE.replace("{{otp}}", otp).replace("{{email}}", user.email)
        };

        await transporter.sendMail(mailOptions);

        return res.json({success:true, message: 'OTP sent to your email'});

    }catch (error){
        return res.json({success:false, message: error.message});
    }
}

//Reset User Password 
export const resetPassword = async(req, res)=>{
    const {email, otp, newPassword} = req.body;

    if(!email || !otp || !newPassword){
        return res.json({success:false, message: 'Email OTP and new Password are required'});
    }

    try {

        const user = await userModel.findOne({email});
        if(!user){
            return res.json({success:false, message: 'User not found.'});
        }

        if(user.resetOtp ==="" || user.resetOtp !== otp){
            return res.json({success:false, message: 'Invaalid OTP'});
        }

        if(user.resetOtpExpireAt<Date.now()){
            return res.json({success:false, message: 'OTP expired'});
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        user.password = hashedPassword;
        user.resetOtp = '';
        user.resetOtpExpireAt = 0;

        await user.save();
        return res.json({success:true, message: 'Password has been reset successfully '});

    } catch(error){
        return res.json({success:false, message: error.message});
    }
}