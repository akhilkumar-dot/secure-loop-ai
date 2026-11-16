// Sample 11: Express Session Cookie missing secure flag (Vulnerable)
// Source: OWASP Top 10 (A05:2021 Security Misconfiguration)
// License: CC-BY-SA-4.0

const express = require('express');
const session = require('express-session');
const app = express();

app.use(session({
  name: 'sess_id',
  secret: 'super-secret-key-12345',
  cookie: {
    // Vulnerability: secure flag is omitted, allowing transmission over plaintext HTTP
    httpOnly: true,
    maxAge: 3600000
  }
}));

