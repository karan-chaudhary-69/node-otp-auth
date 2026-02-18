const serverless = require('serverless-http');
const express = require('express');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const Otp = require('../models/Otp');

const app = express();
app.use(express.json());

// Reuse MongoDB connection
let isConnected = false;
async function connectDB() {
    if (isConnected) return;
    await mongoose.connect(process.env.MONGO_URI);
    isConnected = true;
}

// Nodemailer transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

// Send OTP
app.post('/send-otp', async (req, res) => {
    try {
        await connectDB();
        const { email } = req.body;
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const hashedOtp = await bcrypt.hash(otp, 10);

        await Otp.findOneAndUpdate(
            { email },
            { otp: hashedOtp, createdAt: new Date() },
            { upsert: true, new: true }
        );

        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'OTP Verification',
            text: `Your OTP is ${otp}`
        });

        res.status(200).send('OTP sent!');
    } catch (err) {
        console.error('Error in send-otp:', err.message);
        res.status(500).send('Internal Server Error');
    }
});

// Verify OTP
app.post('/verify-otp', async (req, res) => {
    try {
        await connectDB();
        const { email, otp } = req.body;
        const record = await Otp.findOne({ email });
        if (!record) return res.status(400).send('No OTP or expired');

        const isValid = await bcrypt.compare(otp, record.otp);
        if (!isValid) return res.status(400).send('Invalid OTP');

        await Otp.deleteOne({ email });
        res.status(200).send('✅ OTP verified!');
    } catch (err) {
        console.error('Error in verify-otp:', err.message);
        res.status(500).send('Internal Server Error');
    }
});

// Export handler for Vercel
module.exports = serverless(app);