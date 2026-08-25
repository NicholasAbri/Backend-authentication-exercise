const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");
const User = require("../models/User");
const authenticate = require("../middleware/authenticate");

const router = express.Router();

/*
|--------------------------------------------------------------------------
| POST /auth/signup
|--------------------------------------------------------------------------
*/

router.post(
  "/signup",

  // Validation rules
  [
    body("name").trim().notEmpty().withMessage("Name is required"),

    body("email")
      .trim()
      .isEmail()
      .withMessage("Please provide a valid email")
      .normalizeEmail(),

    body("password")
      .isLength({ min: 8 })
      .withMessage("Password must be at least 8 characters long"),
  ],

  async (req, res) => {
    try {
      // Check validation errors
      const errors = validationResult(req);

      if (!errors.isEmpty()) {
        return res.status(400).json({
          message: "Validation failed",
          errors: errors.array(),
        });
      }

      const { name, email, password } = req.body;

      // Check if email already exists
      const existingUser = await User.findOne({ email });

      if (existingUser) {
        return res.status(400).json({
          message: "Email already registered",
        });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Create user
      const user = await User.create({
        name,
        email,
        password: hashedPassword,
      });

      // Never return password
      return res.status(201).json({
        message: "User registered successfully",
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
        },
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        message: "Server error",
      });
    }
  },
);

/*
|--------------------------------------------------------------------------
| POST /auth/signin
|--------------------------------------------------------------------------
*/

router.post(
  "/signin",

  [
    body("email")
      .trim()
      .notEmpty()
      .withMessage("Email is required")
      .isEmail()
      .withMessage("Please provide a valid email")
      .normalizeEmail(),

    body("password").notEmpty().withMessage("Password is required"),
  ],

  async (req, res) => {
    try {
      const errors = validationResult(req);

      if (!errors.isEmpty()) {
        return res.status(400).json({
          message: "Validation failed",
          errors: errors.array(),
        });
      }

      const { email, password } = req.body;

      const user = await User.findOne({ email });

      if (!user) {
        return res.status(400).json({
          message: "Invalid email or password",
        });
      }

      const passwordMatches = await bcrypt.compare(password, user.password);

      if (!passwordMatches) {
        return res.status(400).json({
          message: "Invalid email or password",
        });
      }

      // Create JWT
      const token = jwt.sign(
        {
          id: user._id,
        },
        process.env.JWT_SECRET,
        {
          expiresIn: process.env.JWT_EXPIRES_IN,
        },
      );

      return res.status(200).json({
        message: "Sign in successful",
        token,
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
        },
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        message: "Server error",
      });
    }
  },
);

/*
|--------------------------------------------------------------------------
| GET /auth/me
|--------------------------------------------------------------------------
*/

router.get("/me", authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");

    if (!user) {
      return res.status(401).json({
        message: "User not found",
      });
    }

    return res.status(200).json({
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    console.error(error);

    return res.status(500).json({
      message: "Server error",
    });
  }
});

module.exports = router;
