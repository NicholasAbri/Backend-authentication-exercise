const express = require("express");
const bcrypt = require("bcrypt");
const { body, validationResult } = require("express-validator");
const User = require("../models/User");

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

  // Validation rules
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
      // Check validation errors
      const errors = validationResult(req);

      if (!errors.isEmpty()) {
        return res.status(400).json({
          message: "Validation failed",
          errors: errors.array(),
        });
      }

      const { email, password } = req.body;

      // Find user by email
      const user = await User.findOne({ email });

      /*
       * Do NOT reveal whether the email exists.
       * Use the same response for:
       * - wrong email
       * - wrong password
       */

      if (!user) {
        return res.status(400).json({
          message: "Invalid email or password",
        });
      }

      // Compare password
      const passwordMatches = await bcrypt.compare(password, user.password);

      if (!passwordMatches) {
        return res.status(400).json({
          message: "Invalid email or password",
        });
      }

      // Successful login
      // Never return the password or password hash
      return res.status(200).json({
        message: "Sign in successful",
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

module.exports = router;
