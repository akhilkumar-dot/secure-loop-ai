// Source: OWASP CheatSheetSeries (https://github.com/OWASP/CheatSheetSeries)
// Commit: 772648fb121bf35be9c25d883b63297a7604d550
// File: cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.md
// License: CC-BY-SA-4.0
// Labelled: safe_control (CWE-79) by security-team at 2026-11-20

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderEscapedBanner() {
  const params = new URLSearchParams(window.location.search);
  const userGreeting = escapeHtml(params.get('msg') || 'Guest');
  // Safe: explicit entity escaping eliminates executable script tags from rendered markup
  const banner = document.getElementById('banner');
  if (banner) banner.innerHTML = '<span>Welcome, ' + userGreeting + '</span>';
}
