// Sample 18: Hardcoded Credentials (Vulnerable)
// Source: OWASP Benchmark / CWE-798
// License: CC-BY-SA-4.0

const mysql = require('mysql2');

// Vulnerability: plaintext sensitive database credentials in code
const connection = mysql.createConnection({
  host: 'db.prod.internal',
  user: 'admin',
  password: 'ProductionSecretPassword2026!'
});

module.exports = connection;

