// Source: OWASP NodeGoat (https://github.com/OWASP/NodeGoat)
// Commit: a242c7cb637c3725c4ef959f6323cf14a51e6ce9
// File: app/routes/allocations.js
// License: Apache-2.0
// Labelled: vulnerable (CWE-502) by security-team at 2026-11-20

const express = require('express');
const vm = require('vm');
const router = express.Router();

router.post('/formula/eval', (req, res) => {
  const expression = req.body.formula;
  // Vulnerability: vm.runInThisContext executes untrusted code with direct access to current global object
  const result = vm.runInThisContext(expression);
  res.json({ result: String(result) });
});

module.exports = router;
