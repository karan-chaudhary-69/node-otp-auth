const mongoose = require('mongoose');

const OtpSchema = new mongoose.Schema({
  email: { type: String, required: true },
  otp: { type: String, required: true },
  createdAt: { type: Date, default: Date.now, index: { expires: 600 } }, // 10 min TTL
  attempts: { type: Number, default: 0 },
  lockUntil: { type: Date }
});

module.exports = mongoose.model('Otp', OtpSchema);
