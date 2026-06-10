const DASH = "http://127.0.0.1:8000/";

const COLORS = {
  phishing: "#f85149",
  suspicious: "#d29922",
  legitimate: "#2ea043",
  error: "#8b98a5",
};

function render(result, tab) {
  const body = document.getElementById("body");

  if (!result) {
    body.innerHTML = `<div class="host">${escapeHtml(tab?.url || "")}</div>
      <p style="color:#8b98a5;font-size:13px">No scan yet for this tab.</p>
      <button id="rescan">Scan now</button>
      <span class="open-dash" id="dash">Open analyst dashboard →</span>`;
    wire(tab);
    return;
  }

  if (result.verdict === "error") {
    body.innerHTML = `<span class="badge error">backend offline</span>
      <p style="color:#8b98a5;font-size:12px;margin-top:10px">
      Start the API: <code>cd backend &amp;&amp; python main.py</code></p>
      <button id="rescan">Retry</button>
      <span class="open-dash" id="dash">Open analyst dashboard →</span>`;
    wire(tab);
    return;
  }

  const pct = Math.round((result.risk_score || 0) * 100);
  const color = COLORS[result.verdict];
  const reasons = (result.reasons || []).map((r) => `<li>${escapeHtml(r)}</li>`).join("");
  body.innerHTML = `
    <span class="badge ${result.verdict}">${result.verdict}</span>
    <div class="host">${escapeHtml(result.hostname || tab?.url || "")}</div>
    <div style="font-size:12px;color:#8b98a5">Risk score: ${pct}% &middot; ${result.latency_ms ?? "?"} ms</div>
    <div class="bar"><div class="fill" style="width:${pct}%;background:${color}"></div></div>
    <ul>${reasons}</ul>
    <button id="rescan">Re-scan with threat intel</button>
    <span class="open-dash" id="dash">Open analyst dashboard →</span>`;
  wire(tab);
}

function wire(tab) {
  const dash = document.getElementById("dash");
  if (dash) dash.onclick = () => chrome.tabs.create({ url: DASH });
  const rescan = document.getElementById("rescan");
  if (rescan && tab) {
    rescan.onclick = () => {
      rescan.textContent = "Scanning…";
      chrome.runtime.sendMessage(
        { type: "RESCAN", tabId: tab.id, url: tab.url },
        (res) => render(res, tab)
      );
    };
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
  chrome.runtime.sendMessage({ type: "GET_RESULT", tabId: tab.id }, (res) =>
    render(res, tab));
});
