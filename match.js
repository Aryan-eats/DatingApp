const mongoose = require('mongoose');

const matchSchema = new mongoose.Schema({
  userId1: {
    type: String,
    required: true,
  },
  userId2: {
    type: String,
    required: true,
  },
  matchedAt: {
    type: Date,
    default: Date.now,
  },
  messages: [{
    senderId: String,
    message: String,
    timestamp: Date,
  }]
});

module.exports = mongoose.model('Match', matchSchema);
