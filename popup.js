let currentTab = null;

document.addEventListener("DOMContentLoaded", async () => {
  await refreshCurrentTab();
  await updatePopup();

  document.getElementById("refreshBtn").addEventListener("click", async () => {
    await refreshCurrentTab();
    await updatePopup();
  });
});

async function refreshCurrentTab() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  currentTab = tabs[0] || null;
}

function isSupportedUrl(urlStr) {
  try {
    const u = new URL(urlStr);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

async function updatePopup() {
  if (!currentTab?.id || !currentTab.url || !isSupportedUrl(currentTab.url)) {
    setText("currentSiteUrl", "No website");
    setText("siteStatus", "Open a normal website tab (http/https).");
    setText("anomalyScore", "0");
    renderList("permissionsList", [{ left: "Permissions", right: "Unavailable" }]);
    renderList("issuesList", [{ left: "DOM", right: "No data" }]);
    return;
  }

  const hostname = new URL(currentTab.url).hostname;
  setText("currentSiteUrl", hostname);
  setText("siteStatus", "Analyzing…");

  // Ask the content script for DOM + permissions
  let res = null;
  try {
    res = await chrome.tabs.sendMessage(currentTab.id, { type: "GET_DOM_AND_PERMISSIONS" });
  } catch (e) {
    // This usually means content script didn't load (manifest mismatch / missing host perms)
    setText("siteStatus", "Can’t analyze this page (content script not running).");
    setText("anomalyScore", "0");
    renderList("permissionsList", [{ left: "Permissions", right: "Unavailable" }]);
    renderList("issuesList", [{ left: "DOM", right: "Unavailable" }]);
    return;
  }

  const score = clampNumber(res?.anomalyScore ?? 0, 0, 100);
  setText("anomalyScore", String(score));

  // Permissions list
  const perms = Array.isArray(res?.sitePermissions) ? res.sitePermissions : [];
  if (perms.length === 0) {
    renderList("permissionsList", [{ left: "Permissions", right: "No data" }]);
  } else {
    renderList(
      "permissionsList",
      perms.map(p => ({ left: p.name, right: prettifyPermissionState(p.state) }))
    );
  }

  // DOM issues in simple English
  const issues = Array.isArray(res?.domIssues) ? res.domIssues : [];
  if (issues.length === 0) {
    renderList("issuesList", [{ left: "DOM", right: "No obvious issues detected." }]);
    setText("siteStatus", "✅ No obvious DOM issues detected");
  } else {
    // show up to 6
    renderList(
      "issuesList",
      issues.slice(0, 6).map(i => ({ left: "•", right: simplifyIssueMessage(i) }))
    );
    setText("siteStatus", "⚠️ Suspicious DOM patterns detected");
  }
}

function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function renderList(containerId, rows) {
  const el = document.getElementById(containerId);
  if (!el) return;
  el.innerHTML = "";

  rows.forEach(r => {
    const row = document.createElement("div");
    row.className = "threat-item";
    row.innerHTML = `
      <span class="threat-message">${escapeHtml(r.left)}</span>
      <span class="threat-confidence">${escapeHtml(r.right)}</span>
    `;
    el.appendChild(row);
  });
}

function clampNumber(n, min, max) {
  const x = Number(n);
  if (Number.isNaN(x)) return min;
  return Math.max(min, Math.min(max, x));
}

function prettifyPermissionState(state) {
  if (state === "granted") return "Granted ✅";
  if (state === "denied") return "Denied ❌";
  if (state === "prompt") return "Not asked (Prompt)";
  if (state === "default") return "Not asked (Default)";
  return String(state || "Unknown");
}

function simplifyIssueMessage(issue) {
  const msg = issue?.message || issue?.type || "Suspicious DOM pattern";
  // keep it simple; trim very long messages
  return msg.length > 120 ? msg.slice(0, 117) + "..." : msg;
}

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
