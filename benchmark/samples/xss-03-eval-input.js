// Sample 7: Eval of User Input (Vulnerable)
// Source: OWASP NodeGoat (contributions.js)
// License: Apache-2.0

const router = require('express').Router();

router.post("/contributions", function(req, res) {
  const contribution = req.body.contribution;
  // Vulnerability: user-supplied input evaluated directly
  eval(contribution);
  res.json({ status: "processed" });
});

module.exports = router;

