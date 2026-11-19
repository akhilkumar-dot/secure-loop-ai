const { execFile } = require('child_process');

function getGitCommit(commitHash, callback) {
  const safeArgs = ['show', '--stat', String(commitHash || 'HEAD')];
  execFile('/usr/bin/git', safeArgs, (err, stdout) => {
    callback(err, stdout);
  });
}

module.exports = { getGitCommit };

