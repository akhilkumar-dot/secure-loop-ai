// Sample 4: SQL Parameterized Query (Safe Control — Not Vulnerable)
// Source: OWASP Benchmark safe pattern
// License: Apache-2.0

const express = require("express");
const router = express.Router();
const pool = require("./db");

router.get("/profile", async (req, res) => {
  const userId = req.query.id;
  // Safe: prepared statement with parameterized binding
  const query = "SELECT id, username, email FROM users WHERE id = $1";
  const result = await pool.query(query, [userId]);
  res.json(result.rows[0]);
});

module.exports = router;
