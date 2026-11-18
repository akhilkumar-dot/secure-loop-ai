// Sample 1: SQL Injection via query string concat (Vulnerable)
// Source: OWASP NodeGoat (contributions.js)
// License: Apache-2.0

const express = require("express");
const router = express.Router();
const db = require("./db");

router.get("/user", async (req, res) => {
  const userId = req.query.userId;
  // Vulnerability: user input directly interpolated into SQL
  const query = "SELECT * FROM users WHERE id = '" + userId + "' AND status = 'active'";
  const results = await db.query(query);
  res.json(results);
});

module.exports = router;
