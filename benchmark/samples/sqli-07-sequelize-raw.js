// Source: OWASP NodeGoat (https://github.com/OWASP/NodeGoat)
// Commit: a242c7cb637c3725c4ef959f6323cf14a51e6ce9
// File: app/routes/allocations.js
// License: Apache-2.0
// Labelled: vulnerable (CWE-89) by security-team at 2026-11-20

const express = require('express');
const router = express.Router();
const sequelize = require('../models/db');

router.post('/allocations/search', async (req, res) => {
  const asset = req.body.asset;
  // Vulnerability: raw sequelize query with unescaped user parameter interpolation
  const results = await sequelize.query(
    "SELECT asset, total, risk FROM allocations WHERE asset LIKE '%" + asset + "%'"
  );
  res.json(results);
});

module.exports = router;
