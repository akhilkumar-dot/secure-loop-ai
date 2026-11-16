// Sample 16: Safe JSON deserialization with strict parsing (Safe Control — Not Vulnerable)
// Source: OWASP Secure Coding Practices
// License: CC-BY-SA-4.0

const express = require('express');
const router = express.Router();

router.post('/preferences', (req, res) => {
  try {
    // Safe: JSON.parse cannot construct object instances or invoke code
    const prefs = JSON.parse(req.body.payload);
    res.json({ theme: String(prefs.theme || 'dark') });
  } catch (e) {
    res.status(400).json({ error: "Invalid JSON" });
  }
});

module.exports = router;

