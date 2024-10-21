require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('./models/user');
const Match = require('./models/match');
const Message = require('./models/messages');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
  tls: true,
  tlsAllowInvalidCertificates: true,
})
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.error('MongoDB connection error:', err));

app.use(express.json());

// Middleware to authenticate users using JWT
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ message: 'Access token required' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Register route
app.post('/register', async (req, res) => {
  const { name, email, password, bio, age, gender, interests, profilePics } = req.body;
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: 'Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = new mongoose.Types.ObjectId().toString();

    const newUser = new User({
      userId, name, email, password: hashedPassword, bio, age, gender, interests, profilePics
    });
    await newUser.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Error registering user:', error.message);
    res.status(500).send('Error registering user');
  }
});

// Login route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (user && await bcrypt.compare(password, user.password)) {
      const token = jwt.sign({ userId: user.userId }, process.env.JWT_SECRET, { expiresIn: '1h' });
      res.json({ userId: user.userId, token, message: 'Login successful' });
    } else {
      res.status(401).json({ message: 'Invalid email or password' });
    }
  } catch (error) {
    console.error('Error logging in:', error);
    res.status(500).send('Error logging in');
  }
});

// Fetch user profiles (for swiping)
app.get('/profiles', authenticateToken, async (req, res) => {
  try {
    const profiles = await User.find({ userId: { $ne: req.user.userId } });
    res.json(profiles);
  } catch (error) {
    console.error('Error fetching profiles:', error);
    res.status(500).send('Error fetching profiles');
  }
});

// Like/Dislike a user
app.post('/like', authenticateToken, async (req, res) => {
  const { likedUserId } = req.body;
  const userId = req.user.userId;

  try {
    const user = await User.findOne({ userId });
    const likedUser = await User.findOne({ userId: likedUserId });

    if (!user || !likedUser) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Add liked user to the user's liked list
    if (!user.likedUsers.includes(likedUserId)) {
      user.likedUsers.push(likedUserId);
      await user.save();
    }

    // Check if likedUser has also liked the user (i.e., it's a match)
    if (likedUser.likedUsers.includes(userId)) {
      // Create a match entry
      const match = new Match({ userId1: userId, userId2: likedUserId });
      await match.save();

      // Add each other to matches list
      user.matches.push(likedUserId);
      likedUser.matches.push(userId);
      await user.save();
      await likedUser.save();

      return res.json({ message: 'It\'s a match!' });
    }

    res.json({ message: 'User liked successfully' });
  } catch (error) {
    console.error('Error liking user:', error);
    res.status(500).send('Error liking user');
  }
});

// Messaging between matched users
app.post('/messages', authenticateToken, async (req, res) => {
  const { receiverId, message } = req.body;
  const senderId = req.user.userId;

  try {
    const match = await Match.findOne({
      $or: [
        { userId1: senderId, userId2: receiverId },
        { userId1: receiverId, userId2: senderId },
      ],
    });

    if (!match) {
      return res.status(403).json({ message: 'You are not matched with this user' });
    }

    const newMessage = new Message({ senderId, receiverId, message });
    await newMessage.save();

    res.status(201).json({ message: 'Message sent successfully', newMessage });
  } catch (error) {
    console.error('Error sending message:', error);
    res.status(500).send('Error sending message');
  }
});

// Real-time messaging with Socket.IO
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) {
    return next(new Error('Authentication error'));
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return next(new Error('Invalid token'));
    socket.userId = decoded.userId;
    next();
  });
});

io.on('connection', (socket) => {
  console.log('User connected:', socket.userId);

  socket.on('join room', ({ receiverId }) => {
    const roomId = [socket.userId, receiverId].sort().join('-');
    socket.join(roomId);
    console.log(`User ${socket.userId} joined room ${roomId}`);
  });

  socket.on('private message', async ({ receiverId, message }) => {
    const roomId = [socket.userId, receiverId].sort().join('-');
    const timestamp = new Date();

    const newMessage = new Message({
      senderId: socket.userId,
      receiverId,
      message,
      timestamp,
    });
    await newMessage.save();

    io.to(roomId).emit('private message', {
      senderId: socket.userId,
      message,
      timestamp,
    });
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.userId);
  });
});

server.listen(5000, () => {
  console.log('Server is running on port 5000');
});
