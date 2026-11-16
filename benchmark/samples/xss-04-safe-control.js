// Sample 8: Safe Text Rendering (Safe Control — Not Vulnerable)
// Source: OWASP Secure Coding Practices
// License: CC-BY-SA-4.0

function updateProfileBadge(user) {
  const badge = document.getElementById("username-badge");
  // Safe: textContent escapes all HTML entities automatically
  badge.textContent = user.displayName;
}

