function checkURL() {
  const url = document.getElementById("urlInput").value;

  fetch('/check', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: url })
  })
  .then(res => res.json())
  .then(data => {
    const basicResult = data.result || "⚠️ Could not analyze";
    const virusTotal = data.virustotal || "not_available";

    document.getElementById("resultBox").style.display = "block";
    document.getElementById("basicCheck").innerText = `🛡️ Basic Check: ${basicResult}`;

    if (virusTotal === "clean") {
      document.getElementById("vtCheck").innerText = `🔍 VirusTotal Check: ✅ No known reports`;
      document.getElementById("explanation").innerText = basicResult.includes("❌")
        ? "⚠️ This link looks suspicious even though no antivirus flagged it. Stay alert."
        : "✅ This link appears safe in both checks.";
    } else {
      document.getElementById("vtCheck").innerText = `🔍 VirusTotal Check: 🔄 Not available`;
      document.getElementById("explanation").innerText =
        "⚠️ VirusTotal check is not active. Result shown is based only on pattern detection.";
    }
  })
  .catch(() => {
    document.getElementById("resultBox").style.display = "block";
    document.getElementById("basicCheck").innerText = "❌ Error checking link";
    document.getElementById("vtCheck").innerText = "";
    document.getElementById("explanation").innerText = "⚠️ Something went wrong. Please try again.";
  });
}
