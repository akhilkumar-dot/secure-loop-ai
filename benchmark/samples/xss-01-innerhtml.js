// Sample 5: Reflected XSS via raw innerHTML assignment (Vulnerable)
// Source: OWASP Juice Shop (search.component.ts)
// License: MIT

function renderSearchResults(data) {
  const container = document.getElementById("search-results");
  const query = new URLSearchParams(window.location.search).get("q");
  // Vulnerability: directly inserting unescaped query string into innerHTML
  container.innerHTML = "<h3>Results for: " + query + "</h3>" + data;
}
