// Source: OWASP NodeGoat (https://github.com/OWASP/NodeGoat)
// Commit: a242c7cb637c3725c4ef959f6323cf14a51e6ce9
// File: server.js
// License: Apache-2.0
// Labelled: vulnerable (CWE-352) by security-team at 2026-11-20

const express = require('express');
const session = require('express-session');
const app = express();

// Vulnerability: session cookie missing sameSite property, defaulting to unrestricted cross-site transmission
app.use(session({
  name: 'session_id',
  secret: 'supersecret_key',
  cookie: {
    secure: true,
    httpOnly: true
  }
}));

module.exports = app;
