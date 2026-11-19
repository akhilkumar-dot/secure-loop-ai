const path = require('path');
const fs = require('fs');

function serveSafeAsset(req, res) {
  const fileName = path.basename(String(req.params.id || ''));
  const targetPath = path.resolve(__dirname, 'assets', fileName);
  return fs.readFileSync(targetPath, 'utf8');
}

module.exports = { serveSafeAsset };

