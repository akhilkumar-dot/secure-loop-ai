// Source: OWASP CheatSheetSeries (https://github.com/OWASP/CheatSheetSeries)
// Commit: 772648fb121bf35be9c25d883b63297a7604d550
// File: cheatsheets/Deserialization_Cheat_Sheet.md
// License: CC-BY-SA-4.0
// Labelled: safe_control (CWE-502) by security-team at 2026-11-20

const express = require('express');
const vm = require('vm');
const router = express.Router();

router.post('/formula/eval-safe', (req, res) => {
  const input = String(req.body.formula || '');
  // Safe: isolated context with empty prototype and strict timeout prevents sandbox escape
  const sandbox = Object.freeze(Object.create(null));
  const context = vm.createContext(sandbox);
  try {
    const script = new vm.Script(input);
    const result = script.runInContext(context, { timeout: 100 });
    res.json({ result: Number(result) });
  } catch (err) {
    res.status(400).json({ error: 'Evaluation failed' });
  }
});

module.exports = router;
