// Source: OWASP NodeGoat (https://github.com/OWASP/NodeGoat)
// Commit: a242c7cb637c3725c4ef959f6323cf14a51e6ce9
// File: app/routes/research.js
// License: Apache-2.0
// Labelled: vulnerable (CWE-502) by security-team at 2026-11-20

const express = require('express');
const router = express.Router();

router.post('/parse-config', (req, res) => {
  const rawPayload = req.body.configPayload;
  // Vulnerability: eval() used as deserializer for untrusted JSON/JavaScript string
  const config = eval('(' + rawPayload + ')');
  res.json({ parsed: config.name });
});

module.exports = router;
