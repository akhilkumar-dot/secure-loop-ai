// Source: DVNA (https://github.com/appsecco/dvna)
// Commit: 7cb8f0b0943eb1bfef6f7dc34f3b6105f241a877
// File: routes/account.js
// License: Apache-2.0
// Labelled: vulnerable (CWE-352) by security-team at 2026-11-20

const express = require('express');
const router = express.Router();
const User = require('../models/User');

// Vulnerability: critical state-changing operation (email update) implemented on GET route with no CSRF validation
router.get('/update-email', async (req, res) => {
  const userId = req.session.userId;
  const newEmail = req.query.email;
  await User.findByIdAndUpdate(userId, { email: newEmail });
  res.send('Email updated to ' + newEmail);
});

module.exports = router;
