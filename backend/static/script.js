function checkURL() {
  const url = document.getElementById("urlInput").value.trim();

  if (!url) {
    document.getElementById("result").innerText = "❌ Please enter a valid URL.";
    return;
  }

  fetch('/check', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: url })
  })
  .then(res => res.json())
  .then(data => {
    // Display results
    document.getElementById("basicCheck").innerText = "🛡️ Basic Check: " + data.basic_check;
    document.getElementById("vtCheck").innerText = "🔍 VirusTotal Check: " + data.vt_check;

    // Create or update additional result lines
    const resultBox = document.getElementById("resultBox");

    function updateOrCreateLine(id, label, text) {
      let el = document.getElementById(id);
      if (!el) {
        el = document.createElement("p");
        el.id = id;
        el.style.margin = "5px 0";
        resultBox.insertBefore(el, document.getElementById("explanation"));
      }
      el.innerText = label + ": " + text;
    }

    updateOrCreateLine("gsbCheck", "🧠 Google Safe Browsing", data.gsb_check);
    updateOrCreateLine("sslCheck", "🔐 HTTPS/SSL", data.ssl_check);
    updateOrCreateLine("whoisCheck", "📆 Domain Info", data.whois_check);
    updateOrCreateLine("structureCheck", "🧬 URL Structure", data.structure_check);

    // Explanation logic
    const explanation =
      (data.vt_check.includes("Clean") && data.basic_check.includes("❌"))
        ? "⚠️ VirusTotal shows clean, but basic analysis found it suspicious."
        : (data.vt_check === "🔄 Not available")
          ? "⚠️ VirusTotal check is not active."
          : "✔️ Multiple checks completed. Interpret based on combined results.";

    document.getElementById("explanation").innerText = explanation;
    document.getElementById("resultBox").style.display = "block";
  })
  .catch(() => {
    document.getElementById("result").innerText = "⚠️ Error checking the link.";
  });
}
