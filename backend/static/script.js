function checkURL() {
  const url = document.getElementById("urlInput").value.trim();
  const resultBox = document.getElementById("resultBox");
  const resultText = document.getElementById("result");

  // Clear previous result box contents
  resultText.innerText = "";
  resultBox.style.display = "none";

  if (!url) {
    resultText.innerText = "❌ Please enter a valid URL.";
    return;
  }

  fetch('/check', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: url })
  })
  .then(res => res.json())
  .then(data => {
    // Basic and VirusTotal check results
    document.getElementById("basicCheck").innerText = "🛡️ Basic Check: " + data.basic_check;
    document.getElementById("vtCheck").innerText = "🔍 VirusTotal Check: " + data.vt_check;

    // Function to add/update result lines
    const updateOrCreateLine = (id, label, value) => {
      let el = document.getElementById(id);
      if (!el) {
        el = document.createElement("p");
        el.id = id;
        el.style.margin = "5px 0";
        resultBox.insertBefore(el, document.getElementById("explanation"));
      }
      el.innerText = `${label}: ${value}`;
    };

    // Update dynamic check lines
    updateOrCreateLine("gsbCheck", "🧠 Google Safe Browsing", data.gsb_check);
    updateOrCreateLine("sslCheck", "🔐 HTTPS/SSL", data.ssl_check);
    updateOrCreateLine("whoisCheck", "📆 Domain Info", data.whois_check);
    updateOrCreateLine("structureCheck", "🧬 URL Structure", data.structure_check);

    // 🧠 Final Verdict Logic (Moved here)
    let verdict = "";
    if (data.basic_check.includes("❌") || data.gsb_check.includes("❌")) {
      verdict = "🔴 Be Careful! This link looks suspicious despite being clean in scans.";
    } else if (data.vt_check.includes("malicious") || data.vt_check.includes("suspicious")) {
      verdict = "🔴 Unsafe! This link is flagged by security scanners.";
    } else if (
      data.basic_check.includes("✅") &&
      data.vt_check.includes("✅") &&
      data.gsb_check.includes("✅")
    ) {
      verdict = "🟢 Safe ✅ This link passed all checks. Still, don't share personal info unless you're sure.";
    } else {
      verdict = "🟡 Mixed Results – Proceed with caution.";
    }
     
    document.getElementById("explanation").innerText = verdict;
    document.getElementById("verdict").innerText = verdict;

    resultBox.style.display = "block";
  })
  .catch(() => {
    resultText.innerText = "⚠️ Error checking the link.";
  });
}
