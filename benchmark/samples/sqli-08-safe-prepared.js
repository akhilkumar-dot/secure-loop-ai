// Source: OWASP NodeGoat (https://github.com/OWASP/NodeGoat)
// Commit: a242c7cb637c3725c4ef959f6323cf14a51e6ce9
// File: app/routes/contributions.js
// License: Apache-2.0
// Labelled: safe_control (CWE-89) by security-team at 2026-11-20

const express = require('express');
const router = express.Router();
const db = require('../models/db');

router.get('/profile/safe', async (req, res) => {
  const username = String(req.query.username || '');
  // Safe: prepared statement with positional parameter array binding
  const sql = 'SELECT id, login, email, role FROM users WHERE login = ?';
  const [rows] = await db.query(sql, [username]);
  res.json(rows);
});

module.exports = router;
