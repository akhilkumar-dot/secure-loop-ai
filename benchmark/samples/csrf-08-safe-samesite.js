// Source: OWASP CheatSheetSeries (https://github.com/OWASP/CheatSheetSeries)
// Commit: 772648fb121bf35be9c25d883b63297a7604d550
// File: cheatsheets/Session_Management_Cheat_Sheet.md
// License: CC-BY-SA-4.0
// Labelled: safe_control (CWE-352) by security-team at 2026-11-20

const express = require('express');
const session = require('express-session');
const app = express();

// Safe: session cookie explicitly configured with strict sameSite, httpOnly, and secure flags
app.use(session({
  name: '__Host-sess',
  secret: process.env.SESSION_SECRET || 'fallback_secret_randomized',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: 'strict'
  }
}));

module.exports = app;
