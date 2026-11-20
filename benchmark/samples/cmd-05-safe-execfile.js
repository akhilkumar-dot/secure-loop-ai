// Source: OWASP CheatSheetSeries (https://github.com/OWASP/CheatSheetSeries)
// Commit: 772648fb121bf35be9c25d883b63297a7604d550
// File: cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.md
// License: CC-BY-SA-4.0
// Labelled: safe_control (CWE-78) by security-team at 2026-11-20

const express = require('express');
const { execFile } = require('child_process');
const router = express.Router();

router.get('/ping/safe', (req, res) => {
  const host = String(req.query.host || '127.0.0.1');
  // Safe: execFile with fixed binary name and strict argument array avoids shell interpreter
  execFile('/bin/ping', ['-c', '1', host], (err, stdout) => {
    if (err) return res.status(500).send('Ping failed');
    res.send(stdout);
  });
});

module.exports = router;
