// Source: OWASP NodeGoat (https://github.com/OWASP/NodeGoat)
// Commit: a242c7cb637c3725c4ef959f6323cf14a51e6ce9
// File: app/routes/contributions.js
// License: Apache-2.0
// Labelled: vulnerable (CWE-89) by security-team at 2026-11-20

const express = require('express');
const router = express.Router();
const db = require('../models/db');

router.get('/profile/view', async (req, res) => {
  const username = req.query.username;
  // Vulnerability: user query interpolated directly via template literal into raw SQL
  const sql = `SELECT id, login, email, role FROM users WHERE login = '${username}'`;
  const [rows] = await db.query(sql);
  res.json(rows);
});

module.exports = router;
