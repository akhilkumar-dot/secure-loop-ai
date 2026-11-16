// Sample 17: OS Command Injection via exec (Vulnerable)
// Source: OWASP NodeGoat
// License: Apache-2.0

const { exec } = require('child_process');
const express = require('express');
const router = express.Router();

router.post('/convert', (req, res) => {
  const filename = req.body.filename;
  // Vulnerability: user-controlled input interpolated directly into shell command
  exec('convert ' + filename + ' output.png', (err, stdout) => {
    if (err) return res.status(500).send("Conversion failed");
    res.send("Converted successfully");
  });
});

module.exports = router;

