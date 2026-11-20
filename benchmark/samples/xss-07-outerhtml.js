// Source: OWASP NodeGoat (https://github.com/OWASP/NodeGoat)
// Commit: a242c7cb637c3725c4ef959f6323cf14a51e6ce9
// File: app/assets/js/common.js
// License: Apache-2.0
// Labelled: vulnerable (CWE-79) by security-team at 2026-11-20

function renderNotification(targetElement, message) {
  const hash = decodeURIComponent(window.location.hash.slice(1));
  // Vulnerability: outerHTML replaces element with untrusted markup from URL hash
  targetElement.outerHTML = '<div class="alert">' + hash + ': ' + message + '</div>';
}
