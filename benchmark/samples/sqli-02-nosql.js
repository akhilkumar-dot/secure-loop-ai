// Sample 2: NoSQL Injection via req.body object injection (Vulnerable)
// Source: OWASP Juice Shop
// License: MIT

const express = require("express");
const router = express.Router();
const User = require("../models/User");

router.post("/login", async (req, res) => {
  // Vulnerability: passing raw req.body object to MongoDB findOne allows {$gt: ""} injection
  const user = await User.findOne({
    username: req.body.username,
    password: req.body.password,
  });
  if (user) {
    res.json({ success: true, token: "session-ok" });
  } else {
    res.status(401).json({ error: "Invalid credentials" });
  }
});

module.exports = router;
