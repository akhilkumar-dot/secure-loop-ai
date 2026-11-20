// Source: OWASP NodeGoat (https://github.com/OWASP/NodeGoat)
// Commit: a242c7cb637c3725c4ef959f6323cf14a51e6ce9
// File: server.js
// License: Apache-2.0
// Labelled: vulnerable (CWE-1004) by security-team at 2026-11-20

const express = require('express');
const session = require('express-session');
const app = express();

// Vulnerability: session cookie missing httpOnly attribute, allowing JavaScript DOM access
app.use(session({
  name: 'user_auth',
  secret: 'app_secret_value',
  cookie: {
    secure: true,
    sameSite: 'strict',
    httpOnly: false
  }
}));

module.exports = app;
