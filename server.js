require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

// In-memory storage for OTPs
const otpStorage = new Map();

// Rate limiting
const sendOtpLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 5, // limit each IP to 5 requests per windowMs
    message: 'Too many OTP requests. Please try again later.'
});

const verifyOtpLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 30, // limit each IP to 30 requests per windowMs
    message: 'Too many verification attempts. Please try again later.'
});

// Nodemailer transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
    }
});

// Generate random 4-digit OTP
function generateOTP() {
    return Math.floor(1000 + Math.random() * 9000).toString();
}

// Send OTP endpoint
app.post('/api/send-otp', sendOtpLimiter, async (req, res) => {
    const { email } = req.body;
    
    if (!email) {
        return res.status(400).json({ message: 'Email is required' });
    }
    
    // Check if OTP already exists and is still valid
    const existingOtp = otpStorage.get(email);
    if (existingOtp && existingOtp.expires > Date.now()) {
        return res.status(400).json({ message: 'OTP already sent. Please check your email or wait to request a new one.' });
    }
    
    // Generate new OTP
    const otp = generateOTP();
    const expires = Date.now() + 5 * 60 * 1000; // 5 minutes expiry
    
    // Store OTP
    otpStorage.set(email, { otp, expires });
    
    // Send email
    try {
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Your OTP Verification Code',
            text: `Your OTP verification code is: ${otp}\nThis code will expire in 5 minutes.`,
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #4a90e2;">OTP Verification</h2>
                    <p>Your OTP verification code is:</p>
                    <h1 style="font-size: 24px; letter-spacing: 5px; color: #333;">${otp}</h1>
                    <p>This code will expire in 5 minutes.</p>
                    <p style="color: #999; font-size: 12px;">If you didn't request this code, please ignore this email.</p>
                </div>
            `
        });
        
        res.json({ message: 'OTP sent successfully' });
    } catch (error) {
        console.error('Error sending email:', error);
        res.status(500).json({ message: 'Failed to send OTP email' });
    }
});

// Verify OTP endpoint
app.post('/api/verify-otp', verifyOtpLimiter, (req, res) => {
    const { email, otp } = req.body;
    
    if (!email || !otp) {
        return res.status(400).json({ message: 'Email and OTP are required' });
    }
    
    const storedOtp = otpStorage.get(email);
    
    if (!storedOtp) {
        return res.status(400).json({ message: 'No OTP found for this email. Please request a new one.' });
    }
    
    if (storedOtp.expires < Date.now()) {
        otpStorage.delete(email);
        return res.status(400).json({ message: 'OTP has expired. Please request a new one.' });
    }
    
    if (storedOtp.otp !== otp) {
        return res.status(400).json({ message: 'Invalid OTP. Please try again.' });
    }
    
    // OTP is valid - remove it from storage
    otpStorage.delete(email);
    
    res.json({ message: 'OTP verified successfully!' });
});

// Resend OTP endpoint
app.post('/api/resend-otp', sendOtpLimiter, async (req, res) => {
    const { email } = req.body;
    
    if (!email) {
        return res.status(400).json({ message: 'Email is required' });
    }
    
    // Generate new OTP
    const otp = generateOTP();
    const expires = Date.now() + 5 * 60 * 1000; // 5 minutes expiry
    
    // Store OTP
    otpStorage.set(email, { otp, expires });
    
    // Send email
    try {
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Your New OTP Verification Code',
            text: `Your new OTP verification code is: ${otp}\nThis code will expire in 5 minutes.`,
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #4a90e2;">New OTP Verification</h2>
                    <p>Your new OTP verification code is:</p>
                    <h1 style="font-size: 24px; letter-spacing: 5px; color: #333;">${otp}</h1>
                    <p>This code will expire in 5 minutes.</p>
                    <p style="color: #999; font-size: 12px;">If you didn't request this code, please ignore this email.</p>
                </div>
            `
        });
        
        res.json({ message: 'New OTP sent successfully' });
    } catch (error) {
        console.error('Error sending email:', error);
        res.status(500).json({ message: 'Failed to send OTP email' });
    }
});

// Serve the frontend
app.get('/', (req, res) => {
    res.sendFile('index.html', { root: './public' });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

// Cleanup expired OTPs every hour
setInterval(() => {
    const now = Date.now();
    for (const [email, { expires }] of otpStorage.entries()) {
        if (expires < now) {
            otpStorage.delete(email);
        }
    }
}, 60 * 60 * 1000);
