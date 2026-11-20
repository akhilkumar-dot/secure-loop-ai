// Source: OWASP CheatSheetSeries (https://github.com/OWASP/CheatSheetSeries)
// Commit: 772648fb121bf35be9c25d883b63297a7604d550
// File: cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md
// License: CC-BY-SA-4.0
// Labelled: safe_control (CWE-352) by security-team at 2026-11-20

const express = require('express');
const router = express.Router();

function verifyHeaderCsrf(req, res, next) {
  const headerToken = req.headers['x-csrf-token'];
  const cookieToken = req.cookies && req.cookies['XSRF-TOKEN'];
  // Safe: double-submit cookie comparison verifies request origin matches stored anti-CSRF token
  if (!headerToken || !cookieToken || headerToken !== cookieToken) {
    return res.status(403).json({ error: 'CSRF token verification failed' });
  }
  next();
}

router.post('/api/action', verifyHeaderCsrf, (req, res) => {
  res.json({ ok: true });
});

module.exports = router;
