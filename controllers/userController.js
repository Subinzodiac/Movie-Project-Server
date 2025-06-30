const bcrypt = require('bcrypt');
const User = require('../models/userModel');
const saltRounds = 10;
const jwt = require('jsonwebtoken');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

// Google Authentication Setup
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: '/auth/google/callback', // Ensure this matches your Google Cloud Console settings
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        // Check if user already exists
        const existingUser = await User.findOne({ googleId: profile.id });

        if (existingUser) {
          return done(null, existingUser);
        }

        // If user does not exist, create a new one
        const newUser = new User({
          googleId: profile.id,
          username: profile.displayName,
          email: profile.emails[0].value,
        });

        const savedUser = await newUser.save();
        return done(null, savedUser);
      } catch (err) {
        return done(err, null);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// Google Authentication Controller
const googleAuth = async (req, res) => {
  try {
    const user = req.user;

    // Generate JWT for authenticated user
    const token = jwt.sign({ data: user._id }, process.env.SECRET_KEY, { expiresIn: '24h' });

    // Respond with user data and token
    res.status(200).json({
      token,
      user,
      message: 'Google Authentication Successful',
    });
  } catch (err) {
    console.error('Google Auth Error:', err);
    res.status(500).send('Internal server error');
  }
};

// Register Controller
const register = async (req, res) => {
  try {
    if (!req.body.username || !req.body.email || !req.body.password) {
      return res.status(400).json({ error: "Authentication failed: Missing email, username, password." });
    }

    const existingUser = await User.findOne({ email: req.body.email });
    if (existingUser) {
      return res.status(422).json({ error: "Email already exists" });
    }

    const hash = await bcrypt.hash(req.body.password, saltRounds);

    const user = new User({
      username: req.body.username,
      email: req.body.email,
      password: hash
    });

    await user.save();

    res.status(201).json({ ...user._doc, message: "Successfully Created Account" });

  } catch (error) {
    console.error("Signup error: ", error);
    res.status(500).send("Internal server error");
  }
};

// Signin Controller
const signin = async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: "Authentication failed: Missing email, username, password." });
    }

    const user = await User.findOne({ email }).select("email password username").exec();

    if (!user) {
      return res.status(422).json({ error: "User not found." });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (passwordMatch) {
      const token = jwt.sign({ data: user._id }, process.env.SECRET_KEY, { expiresIn: '24h' });

      return res.status(200).json({ token, ...user._doc, message: "Login Successful" });
    } else {
      return res.status(401).json({ error: "Incorrect Password" });
    }

  } catch (err) {
    console.error("Signin error:", err);
    res.status(500).send("Internal server error");
  }
};

// Update Password Controller
const updatePassword = async (req, res) => {
  try {
    const decoded = req.decoded;
    const userId = decoded.data;

    const { email, newPassword } = req.body;

    if (!email || !newPassword) {
      return res.status(400).json({ error: "Authentication failed: Missing email or new password." });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: "User not found" });
    }

    const hash = bcrypt.hashSync(newPassword, saltRounds);

    const updatedUser = await User.findByIdAndUpdate(userId, { password: hash }, { new: true });

    if (!updatedUser) {
      return res.status(400).json({ error: "User update failed" });
    } else {
      return res.status(200).json({ message: "Updated Password Successfully" });
    }
  } catch (error) {
    console.error("Update password error:", error);
    res.status(500).send("Internal server error");
  }
};

// Get User By ID Controller
const getUserById = async (req, res) => {
  try {
    const decoded = req.decoded;
    const userId = decoded.data;

    if (!userId) return res.status(400).json({ error: "User does not exist!" });

    const user = await User.findById(userId);
    res.status(200).json(user);
  } catch (error) {
    console.error("Data Fetching error:", error);
    res.status(500).send("Internal server error");
  }
};

module.exports = {
  register,
  signin,
  updatePassword,
  getUserById,
  googleAuth,
};
