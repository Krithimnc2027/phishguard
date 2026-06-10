// PhishGuard service worker.
// On every committed top-level navigation, send the URL to the backend for a
// fast (lexical-only) verdict and update the toolbar badge. Phishing verdicts
// raise a desktop notification. Results are cached per-tab for the popup.

const API = "http://127.0.0.1:8000";
const SCAN_TIMEOUT_MS = 1500;

const BADGE = {
  phishing: { text: "!", color: "#f85149" },
  suspicious: { text: "?", color: "#d29922" },
  legitimate: { text: "✓", color: "#2ea043" },
  error: { text: "", color: "#8b98a5" },
};

// tabId -> last scan result
const cache = {};

function setBadge(tabId, verdict) {
  const b = BADGE[verdict] || BADGE.error;
  chrome.action.setBadgeText({ tabId, text: b.text });
  chrome.action.setBadgeBackgroundColor({ tabId, color: b.color });
}

async function scanUrl(url) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), SCAN_TIMEOUT_MS);
  try {
    const res = await fetch(`${API}/api/scan?intel=false`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: ctrl.signal,
    });
    return await res.json();
  } finally {
    clearTimeout(t);
  }
}

function isScannable(url) {
  return url && (url.startsWith("http://") || url.startsWith("https://"));
}

async function handleNavigation(tabId, url) {
  if (!isScannable(url)) {
    setBadge(tabId, "error");
    return;
  }
  try {
    const result = await scanUrl(url);
    cache[tabId] = result;
    setBadge(tabId, result.verdict);
    if (result.verdict === "phishing") {
      chrome.notifications.create(`phish-${tabId}-${Date.now()}`, {
        type: "basic",
        iconUrl: "icons/icon128.png",
        title: "⚠️ PhishGuard: Phishing detected",
        message: `${result.hostname || url}\nRisk ${Math.round(result.risk_score * 100)}%`,
        priority: 2,
      });
    }
  } catch (e) {
    cache[tabId] = { verdict: "error", error: String(e) };
    setBadge(tabId, "error");
  }
}

chrome.webNavigation?.onCommitted?.addListener((details) => {
  if (details.frameId === 0) handleNavigation(details.tabId, details.url);
});

// Fallback for environments without webNavigation: react to tab updates.
chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status === "loading" && tab.url) handleNavigation(tabId, tab.url);
});

chrome.tabs.onRemoved.addListener((tabId) => { delete cache[tabId]; });

// Popup asks for the active tab's cached result.
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === "GET_RESULT") {
    sendResponse(cache[msg.tabId] || null);
  } else if (msg.type === "RESCAN") {
    handleNavigation(msg.tabId, msg.url).then(() =>
      sendResponse(cache[msg.tabId] || null));
    return true; // async response
  }
});
