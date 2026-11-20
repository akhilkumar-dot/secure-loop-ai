// Source: OWASP NodeGoat (https://github.com/OWASP/NodeGoat)
// Commit: a242c7cb637c3725c4ef959f6323cf14a51e6ce9
// File: app/routes/import.js
// License: Apache-2.0
// Labelled: vulnerable (CWE-502) by security-team at 2026-11-20

const express = require('express');
const yaml = require('js-yaml');
const router = express.Router();

router.post('/import/yaml', (req, res) => {
  const yamlString = req.body.data;
  // Vulnerability: yaml.load with default schema parses custom type tags and executes arbitrary code
  const doc = yaml.load(yamlString);
  res.json({ imported: doc });
});

module.exports = router;
