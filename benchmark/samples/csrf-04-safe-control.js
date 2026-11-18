// Sample 12: Express Session with secure cookies and csrf protection (Safe Control)
// Source: OWASP Cheat Sheet Series
// License: CC-BY-SA-4.0

const express = require("express");
const session = require("express-session");
const csrf = require("csurf");
const app = express();

app.use(
  session({
    name: "sess_id",
    secret: process.env.SESSION_SECRET,
    cookie: {
      secure: true,
      httpOnly: true,
      sameSite: "strict",
    },
  }),
);

const csrfProtection = csrf({ cookie: true });
app.use(csrfProtection);
