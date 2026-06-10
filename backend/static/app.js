const API = ""; // same origin

const $ = (id) => document.getElementById(id);
let riskChart;

const VERDICT_COLORS = {
  phishing: "#f85149",
  suspicious: "#d29922",
  legitimate: "#2ea043",
};

async function scan() {
  const url = $("urlInput").value.trim();
  if (!url) return;
  const intel = $("intelToggle").checked;
  const btn = $("scanBtn");
  btn.disabled = true;
  btn.textContent = "Scanning…";
  try {
    const res = await fetch(`${API}/api/scan?intel=${intel}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    const data = await res.json();
    renderResult(data);
    await refresh();
  } catch (e) {
    $("result").classList.remove("hidden");
    $("result").innerHTML = `<span style="color:var(--red)">Error: ${e.message}. Is the backend running?</span>`;
  } finally {
    btn.disabled = false;
    btn.textContent = "Scan";
  }
}

function renderResult(d) {
  const pct = Math.round(d.risk_score * 100);
  const color = VERDICT_COLORS[d.verdict];
  const reasons = (d.reasons || []).map((r) => `<li>${escapeHtml(r)}</li>`).join("");
  const intel = d.intel && Object.keys(d.intel).length
    ? `<pre class="intel-pre">${escapeHtml(JSON.stringify(d.intel, null, 2))}</pre>`
    : "";
  $("result").classList.remove("hidden");
  $("result").innerHTML = `
    <div>
      <span class="verdict-badge verdict-${d.verdict}">${d.verdict}</span>
      <span style="color:var(--muted);margin-left:10px">risk ${pct}% &middot; ${d.latency_ms} ms</span>
    </div>
    <div class="risk-bar"><div class="risk-fill" style="width:${pct}%;background:${color}"></div></div>
    <ul class="reason-list">${reasons}</ul>
    ${intel}
  `;
}

async function refresh() {
  const [stats, history, metrics] = await Promise.all([
    fetch(`${API}/api/stats`).then((r) => r.json()),
    fetch(`${API}/api/history?limit=50`).then((r) => r.json()),
    fetch(`${API}/api/metrics`).then((r) => r.json()),
  ]);
  renderStats(stats);
  renderChart(stats);
  renderHistory(history.scans);
  renderMetrics(metrics);
}

function renderStats(s) {
  $("statTotal").textContent = s.total;
  $("statPhish").textContent = s.phishing;
  $("statSusp").textContent = s.suspicious;
  $("statLegit").textContent = s.legitimate;
}

function renderChart(s) {
  const ctx = $("riskChart");
  const data = [s.phishing, s.suspicious, s.legitimate];
  if (riskChart) {
    riskChart.data.datasets[0].data = data;
    riskChart.update();
    return;
  }
  riskChart = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: ["Phishing", "Suspicious", "Legitimate"],
      datasets: [{
        data,
        backgroundColor: [VERDICT_COLORS.phishing, VERDICT_COLORS.suspicious, VERDICT_COLORS.legitimate],
        borderColor: "#1a2129",
        borderWidth: 2,
      }],
    },
    options: {
      plugins: { legend: { labels: { color: "#e6edf3" } } },
    },
  });
}

function renderMetrics(m) {
  if (m.error) { $("metricsBox").textContent = m.error; return; }
  const topf = (m.top_features || []).slice(0, 5)
    .map((f) => `${f.feature} (${f.importance})`).join(", ");
  $("metricsBox").innerHTML = `
    Algorithm: <b>${m.model}</b><br>
    Accuracy: <b>${(m.accuracy * 100).toFixed(2)}%</b><br>
    Precision: <b>${(m.precision * 100).toFixed(2)}%</b> &middot;
    Recall: <b>${(m.recall * 100).toFixed(2)}%</b><br>
    ROC-AUC: <b>${m.roc_auc}</b><br>
    Inference: <b>${m.single_inference_ms} ms</b><br>
    Top features: <span style="color:var(--muted)">${topf}</span>
  `;
}

function renderHistory(scans) {
  const tbody = document.querySelector("#historyTable tbody");
  tbody.innerHTML = scans.map((s) => {
    const t = new Date(s.ts).toLocaleString();
    const color = VERDICT_COLORS[s.verdict];
    const pct = Math.round(s.risk_score * 100);
    const reasons = (s.reasons || []).slice(0, 2).join("; ");
    return `<tr>
      <td>${t}</td>
      <td class="url-cell">${escapeHtml(s.url)}</td>
      <td><span class="mini-badge" style="background:${color}22;color:${color}">${s.verdict}</span></td>
      <td>${pct}%</td>
      <td style="color:var(--muted)">${escapeHtml(reasons)}</td>
      <td><a class="report-link" onclick="downloadReport(${s.id})">IoC</a></td>
    </tr>`;
  }).join("");
}

async function downloadReport(id) {
  const r = await fetch(`${API}/api/report/${id}`);
  const data = await r.json();
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `phishguard_ioc_${id}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

$("scanBtn").addEventListener("click", scan);
$("urlInput").addEventListener("keydown", (e) => { if (e.key === "Enter") scan(); });
window.downloadReport = downloadReport;
refresh();
