// Sample 3: NoSQL Injection via $where clause (Vulnerable)
// Source: OWASP NodeGoat
// License: Apache-2.0

const router = require("express").Router();
const Allocations = require("../models/Allocations");

router.get("/allocations", function (req, res) {
  const threshold = req.query.threshold;
  // Vulnerability: $where with user string concatenation
  Allocations.find({ $where: "this.amount > " + threshold }, function (err, data) {
    if (err) return res.status(500).send(err);
    res.json(data);
  });
});

module.exports = router;
