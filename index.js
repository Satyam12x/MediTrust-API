const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const nodemailer = require("nodemailer");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const sanitize = require("sanitize-html");

dotenv.config();

// Environment variables
const PORT = process.env.PORT || 5000;
const MONGO_URI =
  process.env.MONGO_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const NODEMAILER_EMAIL = process.env.NODEMAILER_EMAIL;
const NODEMAILER_PASS =
  process.env.NODEMAILER_PASS;

// MongoDB connection
mongoose
  .connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.error("MongoDB Connection Error:", err));

// User Schema
const userSchema = new mongoose.Schema(
  {
    firstName: { type: String, trim: true, default: "" },
    lastName: { type: String, trim: true, default: "" },
    age: { type: Number, min: 18 },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    password: { type: String, required: true, minlength: 6 },
    userType: { type: String, enum: ["donor", "patient", "hospital"] },
    registrationNumber: { type: String, trim: true },
    kycVerified: { type: Boolean, default: false },
    kycDocuments: [{ documentType: String, url: String, verified: Boolean }],
    profilePicture: { type: String },
    location: { type: String, trim: true },
    phone: { type: String, trim: true },
    consentGDPR: { type: Boolean, default: false },
    donationHistory: [
      { type: mongoose.Schema.Types.ObjectId, ref: "Donation" },
    ],
    requestHistory: [{ type: mongoose.Schema.Types.ObjectId, ref: "Request" }],
    certificates: [
      { certificateId: String, blockchainHash: String, url: String },
    ],
    incentives: { type: Number, default: 0 },
    notifications: [
      { type: String, message: String, read: Boolean, createdAt: Date },
    ],
    fraudScore: { type: Number, default: 0, min: 0 },
    isSuspended: { type: Boolean, default: false },
    rememberMe: { type: Boolean, default: false },
    status: {
      type: String,
      enum: ["pending", "completed"],
      default: "pending",
    },
    otp: { type: String },
    otpExpiry: { type: Date },
    tempEmail: { type: String }, // Temporary field for email update
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

userSchema.index({ email: 1 });

// Medicine Schema
const medicineSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    batchNo: { type: String, required: true, unique: true, trim: true },
    expiryDate: { type: Date, required: true },
    image: { type: String },
    quantity: { type: String, required: true },
    donor: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    donorType: { type: String, enum: ["User", "Hospital"], required: true },
    hospital: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    storageConditions: { type: String, trim: true },
    qrCodeUrl: { type: String },
    blockchainHash: { type: String },
    isPrescription: { type: Boolean, default: false },
    isFlagged: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

medicineSchema.index({ batchNo: 1 });

// Request Schema
const requestSchema = new mongoose.Schema(
  {
    requester: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    requesterType: { type: String, enum: ["User"], required: true },
    medicine: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Medicine",
      required: true,
    },
    quantity: { type: String, required: true },
    status: {
      type: String,
      enum: ["pending", "approved", "rejected", "dispatched", "delivered"],
      default: "pending",
    },
    trackingId: { type: String, trim: true },
    gpsLocation: { type: String, trim: true },
    blockchainHash: { type: String },
    prescriptionUpload: { type: String },
    priority: {
      type: String,
      enum: ["low", "medium", "high"],
      default: "medium",
    },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

requestSchema.index({ requester: 1, medicine: 1 });

// Donation Schema
const donationSchema = new mongoose.Schema(
  {
    donor: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    donorType: { type: String, enum: ["User", "Hospital"], required: true },
    medicine: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Medicine",
      required: true,
    },
    recipient: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    recipientType: { type: String, enum: ["User", "Hospital"] },
    status: {
      type: String,
      enum: ["pending", "approved", "dispatched", "received"],
      default: "pending",
    },
    trackingId: { type: String, trim: true },
    qrScanVerified: { type: Boolean, default: false },
    blockchainHash: { type: String },
    expiryAlertSent: { type: Boolean, default: false },
    impact: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

donationSchema.index({ donor: 1, medicine: 1 });

// Log Schema
const logSchema = new mongoose.Schema(
  {
    action: { type: String, required: true },
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    details: { type: Object },
    blockchainHash: { type: String },
    createdAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

logSchema.index({ createdAt: -1 });

// Models
const User = mongoose.model("User", userSchema);
const Medicine = mongoose.model("Medicine", medicineSchema);
const Request = mongoose.model("Request", requestSchema);
const Donation = mongoose.model("Donation", donationSchema);
const Log = mongoose.model("Log", logSchema);

// CORS configuration
const allowedOrigins = ["http://localhost:3000", "http://localhost:5173"];
const corsOptions = {
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true,
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

// Express app setup
const app = express();
app.use(helmet());
app.use(cors(corsOptions));
app.use(express.json());
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: "Too many requests, please try again later" },
  })
);

// Nodemailer transport
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: { user: NODEMAILER_EMAIL, pass: NODEMAILER_PASS },
});

// Utility functions
const generateOTP = () =>
  Math.floor(100000 + Math.random() * 900000).toString();

const sendEmail = async (to, subject, text) => {
  try {
    const mailOptions = { from: NODEMAILER_EMAIL, to, subject, text };
    await transporter.sendMail(mailOptions);
    return true;
  } catch (error) {
    console.error("Email Error:", error);
    return false;
  }
};

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Access denied" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = user;
    next();
  });
};

const ensureOtpVerified = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id).select("status");
    if (!user || user.status !== "completed") {
      await Log.create({
        action: "access_denied",
        user: req.user.id,
        details: { reason: "OTP verification incomplete" },
      });
      return res
        .status(403)
        .json({ error: "Please complete OTP verification" });
    }
    next();
  } catch (error) {
    console.error("OTP Verification Check Error:", error);
    await Log.create({
      action: "otp_verification_check_error",
      user: req.user.id,
      details: { error: error.message },
    });
    res.status(500).json({ error: "Server error" });
  }
};

const sanitizeInput = (input) => {
  if (typeof input === "string") {
    return sanitize(input, { allowedTags: [], allowedAttributes: {} });
  }
  return input;
};

const sanitizeBody = (req, res, next) => {
  for (const key in req.body) {
    if (typeof req.body[key] === "string") {
      req.body[key] = sanitizeInput(req.body[key]);
    }
  }
  next();
};

// Routes
// Signup Route
app.post("/api/signup", sanitizeBody, async (req, res) => {
  try {
    const { email, password, confirmPassword } = req.body;

    if (!email || !password || !confirmPassword) {
      await Log.create({
        action: "signup_failed",
        details: { email, reason: "Missing required fields" },
      });
      return res
        .status(400)
        .json({
          error: "Please provide email, password, and confirm password",
        });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      await Log.create({
        action: "signup_failed",
        details: { email, reason: "Invalid email format" },
      });
      return res
        .status(400)
        .json({ error: "Please enter a valid email address" });
    }
    if (password.length < 6) {
      await Log.create({
        action: "signup_failed",
        details: { email, reason: "Password too short" },
      });
      return res
        .status(400)
        .json({ error: "Password must be at least 6 characters long" });
    }
    if (password !== confirmPassword) {
      await Log.create({
        action: "signup_failed",
        details: { email, reason: "Passwords do not match" },
      });
      return res.status(400).json({ error: "Passwords do not match" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      await Log.create({
        action: "signup_failed",
        details: { email, reason: "Email already registered" },
      });
      return res.status(400).json({ error: "Email already registered" });
    }

    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      email,
      password: hashedPassword,
      status: "pending",
      otp,
      otpExpiry,
    });
    await user.save();

    const emailSent = await sendEmail(
      email,
      "MediTrust OTP Verification",
      `Your OTP is ${otp}. It expires in 10 minutes.`
    );
    if (!emailSent) {
      await Log.create({
        action: "signup_failed",
        user: user._id,
        details: { email, reason: "Failed to send OTP email" },
      });
      return res.status(500).json({ error: "Failed to send OTP email" });
    }

    await Log.create({
      action: "signup_initiated",
      user: user._id,
      details: { email },
    });
    res.status(201).json({ message: "OTP sent to your email", email });
  } catch (error) {
    console.error("Signup Error:", error);
    await Log.create({
      action: "signup_error",
      details: { error: error.message },
    });
    res.status(500).json({ error: "Server error", details: error.message });
  }
});

// Complete Registration Route
app.post("/api/complete-registration", sanitizeBody, async (req, res) => {
  try {
    const {
      email,
      otp,
      firstName,
      lastName,
      age,
      userType,
      agreeTerms,
      registrationNumber,
      location,
    } = req.body;

    if (!email || !otp || !/^\d{6}$/.test(otp)) {
      await Log.create({
        action: "complete_registration_failed",
        details: { email, reason: "Invalid email or OTP format" },
      });
      return res
        .status(400)
        .json({ error: "Please provide a valid email and 6-digit OTP" });
    }
    if (
      !firstName ||
      !lastName ||
      !age ||
      !userType ||
      !agreeTerms ||
      !location
    ) {
      await Log.create({
        action: "complete_registration_failed",
        details: { email, reason: "Missing required fields" },
      });
      return res
        .status(400)
        .json({
          error:
            "Please provide first name, last name, age, user type, location, and agree to terms",
        });
    }
    if (age < 18) {
      await Log.create({
        action: "complete_registration_failed",
        details: { email, reason: "Underage" },
      });
      return res
        .status(400)
        .json({ error: "You must be at least 18 years old" });
    }
    if (!["donor", "patient", "hospital"].includes(userType)) {
      await Log.create({
        action: "complete_registration_failed",
        details: { email, reason: "Invalid user type" },
      });
      return res.status(400).json({ error: "Invalid user type" });
    }
    if (userType === "hospital" && !registrationNumber) {
      await Log.create({
        action: "complete_registration_failed",
        details: { email, reason: "Missing registration number for hospital" },
      });
      return res
        .status(400)
        .json({ error: "Registration number is required for hospitals" });
    }
    if (!agreeTerms) {
      await Log.create({
        action: "complete_registration_failed",
        details: { email, reason: "Terms not agreed" },
      });
      return res.status(400).json({ error: "You must agree to the terms" });
    }
    if (!location || location.length < 2) {
      await Log.create({
        action: "complete_registration_failed",
        details: { email, reason: "Invalid location" },
      });
      return res.status(400).json({ error: "Please provide a valid location" });
    }

    const user = await User.findOne({ email, otp });
    if (!user || user.otpExpiry < new Date()) {
      await Log.create({
        action: "complete_registration_failed",
        details: { email, reason: "Invalid or expired OTP" },
      });
      return res.status(400).json({ error: "Invalid or expired OTP" });
    }
    if (user.status !== "pending") {
      await Log.create({
        action: "complete_registration_failed",
        details: { email, reason: "Registration already completed" },
      });
      return res.status(400).json({ error: "Registration already completed" });
    }

    user.firstName = firstName;
    user.lastName = lastName;
    user.age = age;
    user.userType = userType;
    user.registrationNumber =
      userType === "hospital" ? registrationNumber : undefined;
    user.consentGDPR = agreeTerms;
    user.location = location;
    user.status = "completed";
    user.otp = undefined;
    user.otpExpiry = undefined;
    await user.save();

    const token = jwt.sign(
      { id: user._id, userType: user.userType },
      JWT_SECRET,
      {
        expiresIn: "1h",
      }
    );

    await Log.create({
      action: "complete_registration_success",
      user: user._id,
      details: { email, userType, location },
    });
    res.json({
      message: "Registration completed successfully",
      token,
      user: {
        id: user._id,
        userType: user.userType,
        email: user.email,
        firstName,
        lastName,
        kycVerified: user.kycVerified,
        location,
      },
    });
  } catch (error) {
    console.error("Complete Registration Error:", error);
    await Log.create({
      action: "complete_registration_error",
      details: { error: error.message },
    });
    res.status(500).json({ error: "Server error", details: error.message });
  }
});

// Login Route
app.post("/api/login", sanitizeBody, async (req, res) => {
  try {
    const { email, password, rememberMe } = req.body;
    if (!email || !password) {
      await Log.create({
        action: "login_failed",
        details: { email, reason: "Missing fields" },
      });
      return res.status(400).json({ error: "Please fill in all fields" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      await Log.create({
        action: "login_failed",
        details: { email, reason: "Invalid credentials" },
      });
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      await Log.create({
        action: "login_failed",
        details: { email, reason: "Invalid password" },
      });
      return res.status(401).json({ error: "Invalid credentials" });
    }

    if (user.status !== "completed") {
      await Log.create({
        action: "login_failed",
        details: { email, reason: "OTP verification incomplete" },
      });
      return res
        .status(403)
        .json({ error: "Please complete OTP verification" });
    }

    const token = jwt.sign(
      { id: user._id, userType: user.userType },
      JWT_SECRET,
      {
        expiresIn: rememberMe ? "7d" : "1h",
      }
    );

    await User.findByIdAndUpdate(user._id, { rememberMe });
    await Log.create({
      action: "login_success",
      user: user._id,
      details: { email },
    });
    res.json({
      token,
      user: {
        id: user._id,
        userType: user.userType,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        kycVerified: user.kycVerified,
        location: user.location || "",
      },
    });
  } catch (error) {
    console.error("Login Error:", error);
    await Log.create({
      action: "login_error",
      details: { error: error.message },
    });
    res.status(500).json({ error: "Server error", details: error.message });
  }
});

// Forgot Password Route
app.post("/api/forgot-password", sanitizeBody, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      await Log.create({
        action: "forgot_password_failed",
        details: { email, reason: "Missing email" },
      });
      return res.status(400).json({ error: "Please provide an email address" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      await Log.create({
        action: "forgot_password_failed",
        details: { email, reason: "Email not found" },
      });
      return res.status(404).json({ error: "Email not found" });
    }

    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);

    user.otp = otp;
    user.otpExpiry = otpExpiry;
    await user.save();

    const emailSent = await sendEmail(
      email,
      "MediTrust Password Reset OTP",
      `Your OTP for password reset is ${otp}. It expires in 10 minutes.`
    );
    if (!emailSent) {
      await Log.create({
        action: "forgot_password_failed",
        details: { email, reason: "Failed to send reset OTP email" },
      });
      return res.status(500).json({ error: "Failed to send reset OTP email" });
    }

    await Log.create({ action: "forgot_password_success", details: { email } });
    res.json({ message: "Password reset OTP sent to your email" });
  } catch (error) {
    console.error("Forgot Password Error:", error);
    await Log.create({
      action: "forgot_password_error",
      details: { error: error.message },
    });
    res.status(500).json({ error: "Server error", details: error.message });
  }
});

// Reset Password Route
app.post("/api/reset-password", sanitizeBody, async (req, res) => {
  try {
    const { email, otp, newPassword, confirmPassword } = req.body;
    if (!email || !otp || !newPassword || !confirmPassword) {
      await Log.create({
        action: "reset_password_failed",
        details: { email, reason: "Missing fields" },
      });
      return res
        .status(400)
        .json({ error: "Please provide all required fields" });
    }
    if (!/^\d{6}$/.test(otp)) {
      await Log.create({
        action: "reset_password_failed",
        details: { email, reason: "Invalid OTP format" },
      });
      return res
        .status(400)
        .json({ error: "Please provide a valid 6-digit OTP" });
    }
    if (newPassword.length < 6) {
      await Log.create({
        action: "reset_password_failed",
        details: { email, reason: "Password too short" },
      });
      return res
        .status(400)
        .json({ error: "Password must be at least 6 characters long" });
    }
    if (newPassword !== confirmPassword) {
      await Log.create({
        action: "reset_password_failed",
        details: { email, reason: "Passwords do not match" },
      });
      return res.status(400).json({ error: "Passwords do not match" });
    }

    const user = await User.findOne({ email, otp });
    if (!user || user.otpExpiry < new Date()) {
      await Log.create({
        action: "reset_password_failed",
        details: { email, reason: "Invalid or expired OTP" },
      });
      return res.status(400).json({ error: "Invalid or expired OTP" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.otp = undefined;
    user.otpExpiry = undefined;
    await user.save();

    await Log.create({
      action: "reset_password_success",
      user: user._id,
      details: { email },
    });
    res.json({ message: "Password reset successfully" });
  } catch (error) {
    console.error("Reset Password Error:", error);
    await Log.create({
      action: "reset_password_error",
      details: { error: error.message },
    });
    res.status(500).json({ error: "Server error", details: error.message });
  }
});

// User Profile Route
app.get("/api/user/profile", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select(
      "firstName lastName email phone kycVerified certificates userType status profilePicture location createdAt"
    );
    if (!user) {
      await Log.create({
        action: "profile_fetch_failed",
        user: req.user.id,
        details: { reason: "User not found" },
      });
      return res.status(404).json({ error: "User not found" });
    }
    res.json({
      firstName: user.firstName || "",
      lastName: user.lastName || "",
      email: user.email,
      phone: user.phone || "",
      kycVerified: user.kycVerified,
      certificates: user.certificates || [],
      userType: user.userType,
      status: user.status,
      profilePicture: user.profilePicture || "",
      location: user.location || "Not specified",
      createdAt: user.createdAt || new Date(),
    });
  } catch (error) {
    console.error("Profile Fetch Error:", error);
    await Log.create({
      action: "profile_fetch_error",
      user: req.user.id,
      details: { error: error.message },
    });
    res.status(500).json({ error: "Server error", details: error.message });
  }
});

// Update Email - Send OTP
app.post(
  "/api/user/update-email",
  authenticateToken,
  ensureOtpVerified,
  sanitizeBody,
  async (req, res) => {
    try {
      const { newEmail } = req.body;
      if (!newEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(newEmail)) {
        await Log.create({
          action: "email_update_failed",
          user: req.user.id,
          details: { reason: "Invalid email format" },
        });
        return res
          .status(400)
          .json({ error: "Please provide a valid new email address" });
      }

      const user = await User.findById(req.user.id);
      if (!user) {
        await Log.create({
          action: "email_update_failed",
          user: req.user.id,
          details: { reason: "User not found" },
        });
        return res.status(404).json({ error: "User not found" });
      }

      if (newEmail === user.email) {
        await Log.create({
          action: "email_update_failed",
          user: user._id,
          details: { reason: "New email same as current" },
        });
        return res
          .status(400)
          .json({ error: "New email cannot be the same as current email" });
      }

      const existingUser = await User.findOne({ email: newEmail });
      if (existingUser) {
        await Log.create({
          action: "email_update_failed",
          user: user._id,
          details: { reason: "Email already registered" },
        });
        return res.status(400).json({ error: "Email already registered" });
      }

      const otp = generateOTP();
      const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);

      user.tempEmail = newEmail;
      user.otp = otp;
      user.otpExpiry = otpExpiry;
      await user.save();

      const emailSent = await sendEmail(
        newEmail,
        "MediTrust Email Update OTP",
        `Your OTP for email update is ${otp}. It expires in 10 minutes.`
      );
      if (!emailSent) {
        await Log.create({
          action: "email_update_failed",
          user: user._id,
          details: { reason: "Failed to send OTP email" },
        });
        return res
          .status(500)
          .json({ error: "Failed to send OTP to new email" });
      }

      await Log.create({
        action: "email_update_initiated",
        user: user._id,
        details: { newEmail },
      });
      res.json({ message: "OTP sent to your new email" });
    } catch (error) {
      console.error("Email Update Initiation Error:", error);
      await Log.create({
        action: "email_update_error",
        user: req.user.id,
        details: { error: error.message },
      });
      res.status(500).json({ error: "Server error" });
    }
  }
);

// Verify Email Update OTP
app.post(
  "/api/user/verify-update-email",
  authenticateToken,
  ensureOtpVerified,
  sanitizeBody,
  async (req, res) => {
    try {
      const { newEmail, otp } = req.body;
      if (!newEmail || !otp || !/^\d{6}$/.test(otp)) {
        await Log.create({
          action: "email_update_failed",
          user: req.user.id,
          details: { reason: "Invalid email or OTP format" },
        });
        return res
          .status(400)
          .json({ error: "Please provide new email and valid 6-digit OTP" });
      }

      const user = await User.findById(req.user.id);
      if (!user) {
        await Log.create({
          action: "email_update_failed",
          user: req.user.id,
          details: { reason: "User not found" },
        });
        return res.status(404).json({ error: "User not found" });
      }

      if (
        user.tempEmail !== newEmail ||
        user.otp !== otp ||
        user.otpExpiry < new Date()
      ) {
        await Log.create({
          action: "email_update_failed",
          user: user._id,
          details: { reason: "Invalid or expired OTP" },
        });
        return res.status(400).json({ error: "Invalid or expired OTP" });
      }

      user.email = newEmail;
      user.tempEmail = undefined;
      user.otp = undefined;
      user.otpExpiry = undefined;
      await user.save();

      await Log.create({
        action: "email_update_success",
        user: user._id,
        details: { newEmail },
      });
      res.json({ message: "Email updated successfully" });
    } catch (error) {
      console.error("Email Update Verification Error:", error);
      await Log.create({
        action: "email_update_error",
        user: req.user.id,
        details: { error: error.message },
      });
      res.status(500).json({ error: "Server error" });
    }
  }
);

// Update Phone
app.post(
  "/api/user/update-phone",
  authenticateToken,
  ensureOtpVerified,
  sanitizeBody,
  async (req, res) => {
    try {
      const { newPhone } = req.body;
      if (!newPhone || !/^\+?[1-9]\d{1,14}$/.test(newPhone)) {
        await Log.create({
          action: "phone_update_failed",
          user: req.user.id,
          details: { reason: "Invalid phone number format" },
        });
        return res
          .status(400)
          .json({
            error: "Please provide a valid phone number (e.g., +1234567890)",
          });
      }

      const user = await User.findById(req.user.id);
      if (!user) {
        await Log.create({
          action: "phone_update_failed",
          user: req.user.id,
          details: { reason: "User not found" },
        });
        return res.status(404).json({ error: "User not found" });
      }

      user.phone = newPhone;
      await user.save();

      await Log.create({
        action: "phone_update_success",
        user: user._id,
        details: { newPhone },
      });
      res.json({ message: "Phone number updated successfully" });
    } catch (error) {
      console.error("Phone Update Error:", error);
      await Log.create({
        action: "phone_update_error",
        user: req.user.id,
        details: { error: error.message },
      });
      res.status(500).json({ error: "Server error" });
    }
  }
);

// User Stats Route
app.get(
  "/api/user/stats",
  authenticateToken,
  ensureOtpVerified,
  async (req, res) => {
    try {
      const userId = req.user.id;
      const donations = await Donation.countDocuments({ donor: userId });
      const requests = await Request.countDocuments({ requester: userId });
      const completedTransactions = await Donation.countDocuments({
        donor: userId,
        status: "received",
      });
      const activeRequests = await Request.countDocuments({
        requester: userId,
        status: { $in: ["pending", "approved", "dispatched"] },
      });
      const livesHelped = await Donation.aggregate([
        {
          $match: {
            donor: new mongoose.Types.ObjectId(userId),
            status: "received",
          },
        },
        { $group: { _id: null, totalImpact: { $sum: "$impact" } } },
      ]);

      const trustScore = 95; // Placeholder
      const impactScore =
        Math.min(Math.round(livesHelped[0]?.totalImpact / 10) || 0, 100) + "%";

      res.json({
        totalDonations: donations,
        activeRequests,
        completedTransactions,
        impactScore,
        livesHelped: livesHelped[0]?.totalImpact || 0,
        trustScore: `${trustScore}%`,
        donationChange: "+0%",
        requestChange: "+0%",
        transactionChange: "+0%",
        impactChange: "+0%",
      });
    } catch (error) {
      console.error("Stats Fetch Error:", error);
      await Log.create({
        action: "stats_fetch_error",
        user: req.user.id,
        details: { error: error.message },
      });
      res.status(500).json({ error: "Server error" });
    }
  }
);

// User Requests Route
app.get(
  "/api/user/requests",
  authenticateToken,
  ensureOtpVerified,
  async (req, res) => {
    try {
      const requests = await Request.find({ requester: req.user.id })
        .populate("medicine", "name")
        .lean();
      const formattedRequests = requests.map((req) => ({
        id: req._id.toString(),
        medicine: req.medicine?.name || "Unknown Medicine",
        quantity: req.quantity,
        status: req.status,
        date: req.createdAt,
        priority: req.priority,
      }));
      res.json(formattedRequests);
    } catch (error) {
      console.error("Requests Fetch Error:", error);
      await Log.create({
        action: "requests_fetch_error",
        user: req.user.id,
        details: { error: error.message },
      });
      res.status(500).json({ error: "Server error" });
    }
  }
);

// User Donations Route
app.get(
  "/api/user/donations",
  authenticateToken,
  ensureOtpVerified,
  async (req, res) => {
    try {
      const donations = await Donation.find({ donor: req.user.id })
        .populate("medicine", "name")
        .populate("recipient", "firstName lastName email")
        .lean();
      const formattedDonations = donations.map((don) => ({
        id: don._id.toString(),
        medicine: don.medicine?.name || "Unknown Medicine",
        quantity: don.quantity || "N/A",
        date: don.createdAt,
        recipient: don.recipient
          ? `${don.recipient.firstName || ""} ${
              don.recipient.lastName || ""
            }`.trim() || don.recipient.email
          : don.recipientType === "Hospital"
          ? "Hospital Recipient"
          : "N/A",
        impact: don.impact,
      }));
      res.json(formattedDonations);
    } catch (error) {
      console.error("Donations Fetch Error:", error);
      await Log.create({
        action: "donations_fetch_error",
        user: req.user.id,
        details: { error: error.message },
      });
      res.status(500).json({ error: "Server error" });
    }
  }
);

// User Notifications Route
app.get(
  "/api/user/notifications",
  authenticateToken,
  ensureOtpVerified,
  async (req, res) => {
    try {
      const user = await User.findById(req.user.id).select("notifications");
      if (!user) {
        await Log.create({
          action: "notifications_fetch_failed",
          user: req.user.id,
          details: { reason: "User not found" },
        });
        return res.status(404).json({ error: "User not found" });
      }
      const formattedNotifications = user.notifications.map((notif, index) => ({
        type:
          notif.type ||
          (index % 3 === 0 ? "success" : index % 3 === 1 ? "info" : "warning"),
        title:
          notif.type === "success"
            ? "Request Approved"
            : notif.type === "info"
            ? "Donation Received"
            : "New Medicine Available",
        message: notif.message || "Notification details",
        time: new Date(notif.createdAt).toLocaleTimeString(),
      }));
      res.json(formattedNotifications);
    } catch (error) {
      console.error("Notifications Fetch Error:", error);
      await Log.create({
        action: "notifications_fetch_error",
        user: req.user.id,
        details: { error: error.message },
      });
      res.status(500).json({ error: "Server error" });
    }
  }
);

// Available Medicines Route (Public)
app.get("/api/medicines/available", async (req, res) => {
  try {
    const medicines = await Medicine.find({
      isFlagged: false,
      quantity: { $ne: "0" },
    })
      .select("name quantity storageConditions")
      .limit(4)
      .lean();
    res.json(medicines);
  } catch (error) {
    console.error("Available Medicines Fetch Error:", error);
    await Log.create({
      action: "available_medicines_fetch_error",
      details: { error: error.message },
    });
    res.status(500).json({ error: "Server error" });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
