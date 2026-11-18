// Sample 13: Unsafe deserialization with node-serialize (Vulnerable)
// Source: OWASP NodeGoat (profile.js)
// License: Apache-2.0

const express = require("express");
const serialize = require("node-serialize");
const app = express();

app.get("/profile", (req, res) => {
  if (req.cookies.profile) {
    const str = Buffer.from(req.cookies.profile, "base64").toString();
    // Vulnerability: node-serialize executes IIFE function strings in payload
    const obj = serialize.unserialize(str);
    res.send("Welcome back " + obj.username);
  } else {
    res.send("No profile cookie found");
  }
});
