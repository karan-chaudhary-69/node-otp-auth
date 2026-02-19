require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const Otp = require('./models/Otp');
const cors = require('cors');
const sgMail = require('@sendgrid/mail');

const app = express();
app.use(express.json());
app.use(express.static('public'));
app.use(cors());

// -----------------
// SendGrid Setup
// -----------------
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// -----------------
// Rate Limiter for /send-otp
// -----------------
const otpLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 5,
  message: "Too many OTP requests. Try again later.",
  skip: (req) => req.method === 'OPTIONS'
});
app.use("/send-otp", otpLimiter);

// -----------------
// MongoDB Connection (Mongoose 7+)
// -----------------
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected Successfully"))
  .catch(err => {
    console.error("❌ MongoDB Connection Error:", err.message);
    process.exit(1);
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
  try {
    const existing = await Otp.findOne({ email });
    if (existing && Date.now() - existing.createdAt < 60000) {
      return res.status(429).send("Please wait before requesting another OTP.");
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const hashedOtp = await bcrypt.hash(otp, 10);

    await Otp.findOneAndUpdate(
      { email },
      { otp: hashedOtp, createdAt: new Date(), attempts: 0 },
      { upsert: true, new: true }
    );

    // Send OTP via SendGrid
    const msg = {
      to: email,
      from: process.env.SENDGRID_FROM_EMAIL, // verified sender
      subject: 'Your OTP Verification Code',
      text: `Your OTP code is: ${otp}. It expires in 10 minutes.`
    };

    await sgMail.send(msg);

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
  try {
    const record = await Otp.findOne({ email });
    if (!record) return res.status(400).send("No OTP request found or OTP expired");

    if (record.lockUntil && record.lockUntil > Date.now()) {
      return res.status(429).send("Too many failed attempts. Try again later.");
    }

    const isValid = await bcrypt.compare(otp, record.otp);
    if (!isValid) {
      const attempts = (record.attempts || 0) + 1;
      if (attempts >= 5) {
        await Otp.updateOne(
          { email },
          { attempts, lockUntil: Date.now() + 5 * 60 * 1000 } // lock 5 min
        );
        return res.status(429).send("Too many failed attempts. Locked for 5 minutes.");
      }
      await Otp.updateOne({ email }, { attempts });
      return res.status(400).send(`Invalid OTP. Attempts left: ${5 - attempts}`);
    }

    // OTP valid
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
