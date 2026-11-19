const path = require('path');
const fs = require('fs');

function serveReport(req, res) {
  const filePath = path.join(__dirname, 'public', req.query.file);
  return fs.readFileSync(filePath, 'utf8');
}

module.exports = { serveReport };

