// Source: OWASP CheatSheetSeries (https://github.com/OWASP/CheatSheetSeries)
// Commit: 772648fb121bf35be9c25d883b63297a7604d550
// File: cheatsheets/Deserialization_Cheat_Sheet.md
// License: CC-BY-SA-4.0
// Labelled: safe_control (CWE-502) by security-team at 2026-11-20

const express = require('express');
const yaml = require('js-yaml');
const router = express.Router();

router.post('/import/yaml-safe', (req, res) => {
  const yamlString = String(req.body.data || '');
  // Safe: FAILSAFE_SCHEMA strictly limits parsed nodes to strings, arrays, and maps only
  try {
    const doc = yaml.load(yamlString, { schema: yaml.FAILSAFE_SCHEMA });
    res.json({ imported: doc });
  } catch (err) {
    res.status(400).json({ error: 'Invalid YAML format' });
  }
});

module.exports = router;
