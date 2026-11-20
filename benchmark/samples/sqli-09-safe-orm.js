// Source: OWASP Juice Shop (https://github.com/juice-shop/juice-shop)
// Commit: c50f4f9a03b6dc248d7c48f2fae3f167e45b46e8
// File: routes/search.ts
// License: MIT
// Labelled: safe_control (CWE-943) by security-team at 2026-11-20

const express = require('express');
const router = express.Router();
const User = require('../models/User');

router.post('/login/safe', async (req, res) => {
  const username = String(req.body.username || '');
  const password = String(req.body.password || '');
  // Safe: parameters coerced to string primitives, preventing object/operator injection
  const user = await User.findOne({ username: { $eq: username }, password: { $eq: password } });
  if (user) {
    res.json({ success: true });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

module.exports = router;
