const mongoose = require('mongoose');

const OtpSchema = new mongoose.Schema({
  email: String,
  otp: String,
  createdAt: Date,
  attempts: Number,
  lockUntil: Date
});

module.exports = mongoose.model('Otp', OtpSchema);
