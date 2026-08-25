const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");

const dns = require("dns");
dns.setServers(["8.8.8.8", "8.8.4.4"]);

const authRoutes = require("./routes/auth");

dotenv.config();

const app = express();

// Middleware
app.use(express.json());

// Routes
app.use("/auth", authRoutes);

// Test route
app.get("/", (req, res) => {
  res.json({
    message: "API is running",
  });
});

// Connect to MongoDB
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("MongoDB connected");

    app.listen(5000, () => {
      console.log("Server running on http://localhost:5000");
    });
  })
  .catch((error) => {
    console.error("MongoDB connection failed:", error);
  });
