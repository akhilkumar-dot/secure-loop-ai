// Source: OWASP CheatSheetSeries (https://github.com/OWASP/CheatSheetSeries)
// Commit: 772648fb121bf35be9c25d883b63297a7604d550
// File: cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md
// License: CC-BY-SA-4.0
// Labelled: safe_control (CWE-352) by security-team at 2026-11-20

const express = require('express');
const csrf = require('csurf');
const router = express.Router();
const csrfProtection = csrf({ cookie: true });

// Safe: all state-changing POST endpoints enforce CSRF token validation
router.post('/transfer', csrfProtection, (req, res) => {
  res.json({ status: 'success', message: 'Transfer executed with verified CSRF token' });
});

module.exports = router;
