// Sample 10: Express app without CSRF middleware (Vulnerable)
// Source: OWASP NodeGoat
// License: Apache-2.0

const express = require('express');
const session = require('express-session');
const app = express();

app.use(session({
  secret: 'app-secret',
  resave: false,
  saveUninitialized: true
}));

// State-changing POST without CSRF token validation
app.post('/transfer', (req, res) => {
  const { recipient, amount } = req.body;
  processTransfer(recipient, amount);
  res.json({ success: true });
});

