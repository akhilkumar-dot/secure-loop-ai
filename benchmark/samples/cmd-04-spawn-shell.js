// Source: DVNA (https://github.com/appsecco/dvna)
// Commit: 7cb8f0b0943eb1bfef6f7dc34f3b6105f241a877
// File: routes/tools.js
// License: Apache-2.0
// Labelled: vulnerable (CWE-78) by security-team at 2026-11-20

const express = require('express');
const { spawn } = require('child_process');
const router = express.Router();

router.get('/ping', (req, res) => {
  const host = req.query.host;
  // Vulnerability: spawn invoked with shell:true and unquoted user-supplied argument
  const proc = spawn('ping -c 1 ' + host, [], { shell: true });
  let output = '';
  proc.stdout.on('data', (d) => { output += d; });
  proc.on('close', () => { res.send(output); });
});

module.exports = router;
