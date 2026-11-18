// Sample 6: Reflected XSS in Express response (Vulnerable)
// Source: OWASP NodeGoat (allocations.js)
// License: Apache-2.0

const express = require("express");
const app = express();

app.get("/welcome", (req, res) => {
  const name = req.query.name;
  // Vulnerability: user-supplied name reflected directly into HTML response
  res.send("<html><body><h1>Welcome back, " + name + "!</h1></body></html>");
});
