// Source: OWASP Juice Shop (https://github.com/juice-shop/juice-shop)
// Commit: c50f4f9a03b6dc248d7c48f2fae3f167e45b46e8
// File: frontend/src/app/Services/socket.service.ts
// License: MIT
// Labelled: vulnerable (CWE-79) by security-team at 2026-11-20

function showWelcomeBanner() {
  const params = new URLSearchParams(window.location.search);
  const userGreeting = params.get('msg') || 'Guest';
  // Vulnerability: document.write with unsanitized URL search parameter
  document.write('<div class="banner">Welcome, ' + userGreeting + '</div>');
}
