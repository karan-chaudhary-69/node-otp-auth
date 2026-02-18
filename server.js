require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const Otp = require('./models/Otp'); // Your OTP model

const cors = require('cors');

const app = express();
app.use(express.json());
app.use(express.static('public')); // Serve all files in public/
app.use(cors());
app.use(cors({
    origin: 'http://127.0.0.1:5001',
    methods: ['GET', 'POST'],
}));

// -----------------
// Rate Limiter
// -----------------
const otpLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 5,
    skip: (req) => req.method === 'OPTIONS', // 👈 ignore preflight
    message: "Too many OTP requests. Try again later."
});

app.use("/send-otp", otpLimiter);

// -----------------
// MongoDB Connection
// -----------------
async function connectDB() {
    try {
        await mongoose.connect(process.env.MONGO_URI, { serverSelectionTimeoutMS: 5000 });
        console.log("✅ MongoDB Connected Successfully");
    } catch (err) {
        console.error("❌ MongoDB Connection Error:", err.message);
        process.exit(1);
    }
}
connectDB();

// -----------------
// Nodemailer Setup
// -----------------
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// -----------------
// Test Route
// -----------------
app.get("/ping", (req, res) => res.send("pong"));

// -----------------
// Send OTP Endpoint
// -----------------
app.post('/send-otp', async (req, res) => {
    const { email } = req.body;

    const existing = await Otp.findOne({ email });

    if (existing) {
        const timePassed = Date.now() - existing.createdAt;
        const cooldown = 60 * 1000; // 1 minute

        if (timePassed < cooldown) {
            return res.status(429).send("Please wait before requesting another OTP.");
        }
    }

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const hashedOtp = await bcrypt.hash(otp, 10);

    try {
        // Save hashed OTP in DB with TTL index on createdAt in the model
        await Otp.findOneAndUpdate(
            { email },
            { otp: hashedOtp, createdAt: new Date() },
            { upsert: true, new: true }
        );

        // Send OTP email
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Your Verification Code",
            text: `Your OTP code is: ${otp}. It expires in 10 minutes.`
        });

        console.log("✅ OTP sent successfully");
        res.status(200).send("OTP sent successfully!");
    } catch (err) {
        console.error("❌ Error sending OTP:", err.message);
        res.status(500).send("Internal Error: " + err.message);
    }
});

// -----------------
// Verify OTP Endpoint
// -----------------
app.post('/verify-otp', async (req, res) => {
    const { email, otp } = req.body;
    console.log(`\n--- Verification Attempt for: ${email} ---`);

    try {
        const record = await Otp.findOne({ email });

        if (!record) {
            return res.status(400).send("No OTP request found or OTP expired");
        }

        // If account is temporarily locked
        if (record.lockUntil && record.lockUntil > Date.now()) {
            return res.status(429).send("Too many failed attempts. Try again later.");
        }

        const isValid = await bcrypt.compare(otp, record.otp);

        if (!isValid) {
            const attempts = (record.attempts || 0) + 1;

            // Lock after 5 failed attempts
            if (attempts >= 5) {
                await Otp.updateOne(
                    { email },
                    {
                        attempts,
                        lockUntil: Date.now() + (5 * 60 * 1000) // lock 5 minutes
                    }
                );
                return res.status(429).send("Too many failed attempts. Locked for 5 minutes.");
            }

            await Otp.updateOne(
                { email },
                { attempts }
            );

            return res.status(400).send(`Invalid OTP. Attempts left: ${5 - attempts}`);
        }

        // Success: delete OTP record
        await Otp.deleteOne({ email });

        res.status(200).send("✅ OTP verified successfully!");
    } catch (err) {
        console.error("❌ OTP Verification Error:", err.message);
        res.status(500).send("Internal Error");
    }
});

// -----------------
// Start Server
// -----------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 Server running on http://0.0.0.0:${PORT}`);
});
