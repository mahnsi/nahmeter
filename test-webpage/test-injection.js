
// --- Utilities (safe) ---
function escapeHTML(s) {
    return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function getQueryParam(name) {
    const u = new URL(location.href);
    return u.searchParams.get(name) || "";
}

function collectSources() {
    return {
    query_q: getQueryParam("q"),
    hash: location.hash ? location.hash.slice(1) : "",
    localStorage_test: localStorage.getItem("dom_injection_test") || "",
    last_postMessage: window.__lastPM || ""
    };
}

function renderSources() {
    const s = collectSources();
    document.getElementById("sources").textContent = JSON.stringify(s, null, 2);
    return s;
}

function getUntrusted() {
    const s = collectSources();
    // pick the first non-empty source, else manual textarea
    return s.query_q || s.hash || s.localStorage_test || s.last_postMessage || document.getElementById("manual").value;
}

// --- Actions ---
document.getElementById("saveLs").addEventListener("click", () => {
    localStorage.setItem("dom_injection_test", document.getElementById("manual").value);
    renderSources();
});

document.getElementById("loadLs").addEventListener("click", () => {
    document.getElementById("manual").value = localStorage.getItem("dom_injection_test") || "";
    renderSources();
});

// postMessage simulation
window.addEventListener("message", (ev) => {
    // Store message payload as a "source" without acting on it.
    window.__lastPM = (typeof ev.data === "string") ? ev.data : JSON.stringify(ev.data);
    renderSources();
});

document.getElementById("sendPm").addEventListener("click", () => {
    // same-window postMessage (safe string)
    window.postMessage("<b>PM</b>: <script>TEST</script>", "*");
});

document.getElementById("sendPmOther").addEventListener("click", () => {
    // simulate "other origin" by tagging payload (still same window here)
    window.postMessage({ from: "other", payload: "<img src=x onerror=TEST>" }, "*");
});

// Sink: innerHTML (escaped)
document.getElementById("doInner").addEventListener("click", () => {
    const untrusted = getUntrusted();
    document.getElementById("outInner").innerHTML =
    "<div><b>Rendered (escaped):</b> " + escapeHTML(untrusted) + "</div>";
});

// Sink: insertAdjacentHTML (escaped)
document.getElementById("doAdj").addEventListener("click", () => {
    const untrusted = getUntrusted();
    const out = document.getElementById("outAdj");
    out.insertAdjacentHTML("beforeend",
    "<div><b>Chunk:</b> " + escapeHTML(untrusted) + "</div>"
    );
});

// Sink: document.write (escaped) into sandboxed iframe
document.getElementById("doWrite").addEventListener("click", () => {
    const untrusted = getUntrusted();
    const iframe = document.getElementById("frame");
    const doc = iframe.contentDocument;
    doc.open();
    doc.write("<!doctype html><meta charset='utf-8'><body style='font-family:system-ui;padding:10px'>");
    doc.write("<h3 style='margin:0 0 8px 0'>iframe document.write</h3>");
    doc.write("<div>Escaped:</div><pre style='background:#f7f7f7;padding:8px;border-radius:8px;white-space:pre-wrap;'>"
    + escapeHTML(untrusted) + "</pre>");
    doc.write("</body>");
    doc.close();
});

// "Script injection" but non-executable
document.getElementById("doScript").addEventListener("click", () => {
    const untrusted = getUntrusted();
    const out = document.getElementById("outScript");

    const s = document.createElement("script");
    s.type = "application/x-test"; // not executed by browser as JS
    s.textContent = "/* test payload (not executed) */\n" + String(untrusted);

    out.textContent = "";
    out.appendChild(document.createTextNode("Appended <script type='application/x-test'> with contents:\n"));
    out.appendChild(document.createElement("br"));
    out.appendChild(document.createTextNode(s.textContent));
    document.body.appendChild(s); // still non-executable due to type
});

// Mutation spam
function spam(n) {
    const host = document.getElementById("outSpam");
    const frag = document.createDocumentFragment();
    for (let i = 0; i < n; i++) {
    const div = document.createElement("div");
    div.textContent = "node-" + i + " " + new Date().toISOString();
    frag.appendChild(div);
    }
    host.textContent = "";
    host.appendChild(frag);
}

document.getElementById("spam10").addEventListener("click", () => spam(10));
document.getElementById("spam200").addEventListener("click", () => spam(200));

// initial render
renderSources();
