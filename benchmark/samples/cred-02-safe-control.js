const mysql = require("mysql2");

const connection = mysql.createConnection({
  host: process.env.DB_HOST || "db.internal.local",
  user: process.env.DB_USER || "app_user",
  password: process.env.DB_PASSWORD || "",
});

module.exports = connection;
