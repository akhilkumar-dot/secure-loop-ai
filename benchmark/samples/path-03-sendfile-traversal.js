// Source: OWASP Juice Shop (https://github.com/juice-shop/juice-shop)
// Commit: c50f4f9a03b6dc248d7c48f2fae3f167e45b46e8
// File: routes/fileServer.ts
// License: MIT
// Labelled: vulnerable (CWE-22) by security-team at 2026-11-20

const express = require('express');
const path = require('path');
const router = express.Router();

router.get('/public/file', (req, res) => {
  const filename = req.query.file;
  // Vulnerability: user-supplied path directly passed to sendFile without resolve/root boundary check
  const targetPath = path.join(__dirname, '../public/uploads', filename);
  res.sendFile(targetPath);
});

module.exports = router;
