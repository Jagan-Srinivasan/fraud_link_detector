// --- Theme Toggle ---
function toggleTheme() {
  const body = document.body;
  body.classList.toggle('dark');
  // Sun/Moon icon swap
  document.getElementById('themeIcon').innerHTML = body.classList.contains('dark')
    ? '<circle cx="12" cy="12" r="9" stroke-width="2"/><path stroke-width="2" d="M21 12.79A9 9 0 1 1 11.21 3a7 7 0 0 0 9.79 9.79z"/>'
    : '<circle cx="12" cy="12" r="9" stroke-width="2"/><path id="themePath" stroke-width="2" d="M12 3V5M12 19v2M4.22 4.22l1.42 1.42M17.66 17.66l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M17.66 6.34l1.42-1.42"/>';
  localStorage.setItem('theme', body.classList.contains('dark') ? 'dark' : 'light');
}
(function() {
  if (localStorage.getItem('theme') === 'dark') {
    document.body.classList.add('dark');
    document.getElementById('themeIcon').innerHTML = '<circle cx="12" cy="12" r="9" stroke-width="2"/><path stroke-width="2" d="M21 12.79A9 9 0 1 1 11.21 3a7 7 0 0 0 9.79 9.79z"/>';
  }
})();

// --- Copy to Clipboard ---
function copyURL() {
  const input = document.getElementById("urlInput");
  input.select();
  input.setSelectionRange(0, 99999);
  document.execCommand("copy");
  document.getElementById('copyIcon').innerHTML = '<svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><path d="M7 9V7a3 3 0 0 1 3-3h5a3 3 0 0 1 3 3v8a3 3 0 0 1-3 3H10a3 3 0 0 1-3-3v-2"/><rect x="5" y="11" width="9" height="7" rx="2"/></svg>';
  setTimeout(() => (document.getElementById('copyIcon').innerHTML =
    '<svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="6" y="4" width="9" height="12" rx="2"/><path d="M9 4V2a2 2 0 0 1 2-2h5a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-2" /></svg>'), 900);
}

// --- Shorten long URLs for display ---
function shortenURL(url, maxLen=64) {
  if (url.length <= maxLen) return url;
  return url.slice(0, 32) + "..." + url.slice(-20);
}

// --- Detect IP-based URL or suspicious port ---
function analyzeURL(url) {
  try {
    let u = new URL(url);
    let isIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(u.hostname);
    let hasPort = !!u.port && u.port !== "80" && u.port !== "443";
    return {isIP, hasPort, port: u.port};
  } catch {
    return {isIP: false, hasPort: false, port: ''};
  }
}

// --- Show loading spinner ---
function showLoader() {
  document.getElementById("loader").style.display = "inline-block";
  document.getElementById("btnText").style.display = "none";
}
function hideLoader() {
  document.getElementById("loader").style.display = "none";
  document.getElementById("btnText").style.display = "inline";
}

// --- Main URL Check Logic ---
function checkURL() {
  const url = document.getElementById("urlInput").value.trim();
  const resultBox = document.getElementById("resultBox");
  const resultText = document.getElementById("result");
  const checksList = document.getElementById("checksList");
  const alertArea = document.getElementById("alertArea");
  const verdictBox = document.getElementById("verdictBox");
  const urlDisplay = document.getElementById("urlDisplay");

  // Reset UI
  resultText.style.display = "none";
  resultText.innerText = "";
  checksList.innerHTML = "";
  alertArea.innerHTML = "";
  verdictBox.innerHTML = "";
  urlDisplay.innerHTML = "";
  resultBox.style.display = "none";
  showLoader();

  if (!url) {
    hideLoader();
    resultText.innerText = "❌ Please enter a valid URL.";
    resultText.style.display = "block";
    return;
  }

  // Show analyzed (shortened) URL
  let urlShort = shortenURL(url, 84);
  let analysis = analyzeURL(url);
  urlDisplay.innerHTML = `<b>🔗 URL:</b> <span title="${url}">${urlShort}</span>`;

  // Additional alerts for IP or port-based URLs
  let extraAlerts = [];
  if (analysis.isIP) extraAlerts.push("⚠️ This link uses an IP address instead of a domain (highly suspicious).");
  if (analysis.hasPort) extraAlerts.push(`⚠️ Uses non-standard port: <b>${analysis.port}</b>`);
  if (extraAlerts.length) {
    alertArea.innerHTML = extraAlerts.map(msg =>
      `<div class="status-line status-red">${msg}</div>`).join("");
    resultBox.style.display = "block";
    hideLoader();
    // Still submit to backend, but mark as dangerous below
  }

  fetch('/check', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: url })
  })
    .then(res => res.json())
    .then(data => {
      function statusClass(val) {
        if (val.includes("❌") || val.includes("malicious") || val.includes("Unsafe") || val.includes("Shortened")) return "status-red";
        if (val.includes("⚠️") || val.includes("Mixed") || val.includes("expiring") || val.includes("suspicious")) return "status-yellow";
        return "status-green";
      }

      const results = [
        {id: "basic", label: "🛡️ Basic Pattern", value: data.basic_check},
        {id: "vt", label: "🔍 VirusTotal", value: data.vt_check},
        {id: "gsb", label: "🧠 Safe Browsing", value: data.gsb_check},
        {id: "ssl", label: "🔐 HTTPS/SSL", value: data.ssl_check},
        {id: "whois", label: "📆 Domain Info", value: data.whois_check},
        {id: "structure", label: "🧬 Structure", value: data.structure_check}
      ];

      checksList.innerHTML = results.map(r =>
        `<div class="status-line ${statusClass(r.value)}"><span>${r.label}</span><span>${r.value}</span></div>`
      ).join("");

      // Final verdict logic
      let verdict = "", verdictClass = "";
      if (extraAlerts.length || data.basic_check.includes("❌") || data.gsb_check.includes("❌") || data.structure_check.includes("❌") || analysis.isIP) {
        verdict = "🔴 Dangerous! This link is highly suspicious or flagged. Do NOT trust!";
        verdictClass = "verdict-red";
      } else if (data.vt_check.includes("malicious") || data.vt_check.includes("suspicious")) {
        verdict = "🔴 Unsafe! This link is flagged by security scanners.";
        verdictClass = "verdict-red";
      } else if (
        data.basic_check.includes("✅") &&
        data.vt_check.includes("✅") &&
        data.gsb_check.includes("✅") &&
        data.ssl_check.includes("✅") &&
        data.whois_check.includes("✅") &&
        data.structure_check.includes("✅")
      ) {
        verdict = "🟢 Safe ✅ This link passed all checks. As always, avoid sharing personal info unless you're 100% sure.";
        verdictClass = "verdict-green";
      } else {
        verdict = "🟡 Mixed Results – Some checks flagged warnings. Proceed with caution!";
        verdictClass = "verdict-yellow";
      }
      verdictBox.className = verdictClass;
      verdictBox.innerText = verdict;

      // Show suggestions if any API returned unavailable/fail
      let suggestions = [];
      if (data.vt_check.includes("Not available") || data.gsb_check.includes("Not available")) {
        suggestions.push("ℹ️ Some security checks are temporarily unavailable. Enable all API keys for maximum protection.");
      }
      if (data.ssl_check.includes("No SSL")) {
        suggestions.push("⚠️ This site does not use HTTPS. Never enter sensitive info on non-SSL sites.");
      }
      if (data.whois_check.includes("Unavailable")) {
        suggestions.push("ℹ️ Domain info couldn't be fetched. Extra caution recommended.");
      }
      if (suggestions.length) {
        alertArea.innerHTML += suggestions.map(s =>
          `<div class="status-line status-yellow">${s}</div>`
        ).join("");
      }

      resultBox.style.display = "block";
      hideLoader();
    })
    .catch(() => {
      hideLoader();
      resultText.innerText = "⚠️ Error checking the link. Please try again in a moment.";
      resultText.style.display = "block";
    });
}
