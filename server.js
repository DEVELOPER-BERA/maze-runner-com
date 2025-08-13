require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const path = require('path');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxies (important for rate limiting behind load balancers/proxies)
app.set('trust proxy', true);

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// In-memory storage for OTPs
const otpStorage = new Map();

// Rate limiting configuration
const sendOtpLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 5, // limit each IP to 5 requests per windowMs
    message: 'Too many OTP requests. Please try again later.',
    standardHeaders: true,
    legacyHeaders: false
});

const verifyOtpLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 30, // limit each IP to 30 requests per windowMs
    message: 'Too many verification attempts. Please try again later.',
    standardHeaders: true,
    legacyHeaders: false
});

// Nodemailer transporter configuration
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
    },
    tls: {
        rejectUnauthorized: false // For local testing only (remove in production)
    }
});

// Generate random 4-digit OTP
function generateOTP() {
    return Math.floor(1000 + Math.random() * 9000).toString();
}

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.status(200).json({ status: 'OK', timestamp: new Date() });
});

// Send OTP endpoint
app.post('/api/send-otp', sendOtpLimiter, async (req, res) => {
    try {
        const { email } = req.body;
        
        if (!email) {
            return res.status(400).json({ 
                success: false,
                message: 'Email is required' 
            });
        }
        
        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ 
                success: false,
                message: 'Please enter a valid email address' 
            });
        }
        
        // Check if OTP already exists and is still valid
        const existingOtp = otpStorage.get(email);
        if (existingOtp && existingOtp.expires > Date.now()) {
            return res.status(400).json({ 
                success: false,
                message: 'OTP already sent. Please check your email or wait to request a new one.' 
            });
        }
        
        // Generate new OTP
        const otp = generateOTP();
        const expires = Date.now() + 5 * 60 * 1000; // 5 minutes expiry
        
        // Store OTP
        otpStorage.set(email, { otp, expires });
        
        // Email options
        const mailOptions = {
            from: `"OTP Service" <${process.env.EMAIL_USER}>`,
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
        };
        
        // Send email
        await transporter.sendMail(mailOptions);
        
        res.json({ 
            success: true,
            message: 'OTP sent successfully' 
        });
    } catch (error) {
        console.error('Error sending OTP:', error);
        res.status(500).json({ 
            success: false,
            message: 'Failed to send OTP email' 
        });
    }
});

// Verify OTP endpoint
app.post('/api/verify-otp', verifyOtpLimiter, (req, res) => {
    try {
        const { email, otp } = req.body;
        
        if (!email || !otp) {
            return res.status(400).json({ 
                success: false,
                message: 'Email and OTP are required' 
            });
        }
        
        // Validate OTP format
        if (otp.length !== 4 || !/^\d+$/.test(otp)) {
            return res.status(400).json({ 
                success: false,
                message: 'OTP must be a 4-digit number' 
            });
        }
        
        const storedOtp = otpStorage.get(email);
        
        if (!storedOtp) {
            return res.status(400).json({ 
                success: false,
                message: 'No OTP found for this email. Please request a new one.' 
            });
        }
        
        if (storedOtp.expires < Date.now()) {
            otpStorage.delete(email);
            return res.status(400).json({ 
                success: false,
                message: 'OTP has expired. Please request a new one.' 
            });
        }
        
        if (storedOtp.otp !== otp) {
            return res.status(400).json({ 
                success: false,
                message: 'Invalid OTP. Please try again.' 
            });
        }
        
        // OTP is valid - remove it from storage
        otpStorage.delete(email);
        
        res.json({ 
            success: true,
            message: 'OTP verified successfully!' 
        });
    } catch (error) {
        console.error('Error verifying OTP:', error);
        res.status(500).json({ 
            success: false,
            message: 'An error occurred during verification' 
        });
    }
});

// Resend OTP endpoint
app.post('/api/resend-otp', sendOtpLimiter, async (req, res) => {
    try {
        const { email } = req.body;
        
        if (!email) {
            return res.status(400).json({ 
                success: false,
                message: 'Email is required' 
            });
        }
        
        // Generate new OTP
        const otp = generateOTP();
        const expires = Date.now() + 5 * 60 * 1000; // 5 minutes expiry
        
        // Store OTP
        otpStorage.set(email, { otp, expires });
        
        // Email options
        const mailOptions = {
            from: `"OTP Service" <${process.env.EMAIL_USER}>`,
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
        };
        
        // Send email
        await transporter.sendMail(mailOptions);
        
        res.json({ 
            success: true,
            message: 'New OTP sent successfully' 
        });
    } catch (error) {
        console.error('Error resending OTP:', error);
        res.status(500).json({ 
            success: false,
            message: 'Failed to resend OTP' 
        });
    }
});

// Serve frontend
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ 
        success: false,
        message: 'Something went wrong!' 
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

// Cleanup expired OTPs every hour
setInterval(() => {
    const now = Date.now();
    let cleaned = 0;
    
    for (const [email, { expires }] of otpStorage.entries()) {
        if (expires < now) {
            otpStorage.delete(email);
            cleaned++;
        }
    }
    
    if (cleaned > 0) {
        console.log(`Cleaned up ${cleaned} expired OTPs`);
    }
}, 60 * 60 * 1000); // Run every hour
