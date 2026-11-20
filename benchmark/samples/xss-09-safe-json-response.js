// Source: OWASP NodeGoat (https://github.com/OWASP/NodeGoat)
// Commit: a242c7cb637c3725c4ef959f6323cf14a51e6ce9
// File: app/routes/memos.js
// License: Apache-2.0
// Labelled: safe_control (CWE-79) by security-team at 2026-11-20

const express = require('express');
const router = express.Router();

router.get('/welcome-safe', (req, res) => {
  const name = String(req.query.name || 'User');
  // Safe: structured application/json API response prevents HTML execution in browser context
  res.json({
    status: 'ok',
    greeting: 'Welcome back, ' + name + '!'
  });
});

module.exports = router;
