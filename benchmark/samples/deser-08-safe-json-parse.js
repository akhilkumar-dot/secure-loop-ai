// Source: OWASP CheatSheetSeries (https://github.com/OWASP/CheatSheetSeries)
// Commit: 772648fb121bf35be9c25d883b63297a7604d550
// File: cheatsheets/Deserialization_Cheat_Sheet.md
// License: CC-BY-SA-4.0
// Labelled: safe_control (CWE-502) by security-team at 2026-11-20

const express = require('express');
const router = express.Router();

router.post('/parse-config/safe', (req, res) => {
  const rawPayload = String(req.body.configPayload || '{}');
  // Safe: JSON.parse parses data only without executing functions or constructors
  try {
    const config = JSON.parse(rawPayload);
    res.json({ parsed: String(config.name || '') });
  } catch (err) {
    res.status(400).json({ error: 'Malformed JSON payload' });
  }
});

module.exports = router;
