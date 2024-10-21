const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  userId: {
    type: String,
    required: true,
    unique: true,
  },
  name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  bio: String,
  age: Number,
  gender: String,
  interests: [String],
  profilePics: [String],
  likedUsers: [String], 
  matches: [String], 
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);
