// Source: OWASP CheatSheetSeries (https://github.com/OWASP/CheatSheetSeries)
// Commit: 772648fb121bf35be9c25d883b63297a7604d550
// File: cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.md
// License: CC-BY-SA-4.0
// Labelled: safe_control (CWE-79) by security-team at 2026-11-20

function renderSafeNotification(container, message) {
  const hash = decodeURIComponent(window.location.hash.slice(1));
  // Safe: DOM createElement and textContent assignment automatically escapes HTML entities
  const alertDiv = document.createElement('div');
  alertDiv.className = 'alert';
  alertDiv.textContent = hash + ': ' + message;
  container.replaceChildren(alertDiv);
}
