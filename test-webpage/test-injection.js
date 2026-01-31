const injectedArea = document.getElementById("injectedArea");

function addToInjected(el) {
injectedArea.appendChild(el);
injectedArea.appendChild(document.createElement("div")).style.height = "10px";
}

function markSuspicious(el, label) {
el.classList.add("sus");
el.setAttribute("data-flag", label);
return el;
}

// 1) Script tag insertion (SAFE): non-executable MIME type
document.getElementById("btnScript").addEventListener("click", () => {
const s = document.createElement("script");
s.type = "application/x-test"; // not executed
s.textContent = "/* demo: non-executing script element */\nconsole.log('not executed');";
document.body.appendChild(s); // still triggers SCRIPT node insertion detector

const note = document.createElement("div");
note.textContent = "Injected a <script> element (non-executing).";
addToInjected(markSuspicious(note, "SCRIPT tag added"));
});

// 2) Inline handler attribute
document.getElementById("btnInline").addEventListener("click", () => {
const b = document.createElement("button");
b.textContent = "“Load more comments” (demo)";
b.setAttribute("onclick", "void 0"); // inline handler attribute (flagged)
b.addEventListener("click", (e) => e.preventDefault()); // keep harmless

addToInjected(markSuspicious(b, "Inline on* handler"));
});

// 3) javascript: href (click prevented)
document.getElementById("btnJsHref").addEventListener("click", () => {
const a = document.createElement("a");
a.href = "javascript:void 0"; // flagged by looksLikeJsUrl()
a.textContent = "Promo link (demo) — href=javascript:… (don’t click)";
a.style.display = "inline-block";
a.addEventListener("click", (e) => e.preventDefault()); // safety

addToInjected(markSuspicious(a, "javascript: URL in href"));
});

// 4) iframe without sandbox
document.getElementById("btnIframe").addEventListener("click", () => {
const iframe = document.createElement("iframe");
// No sandbox attribute on purpose (flagged)
iframe.srcdoc = "<!doctype html><meta charset='utf-8'><body style='font-family:system-ui;padding:10px'>Embedded widget (demo)</body>";
iframe.style.width = "100%";
iframe.style.height = "80px";
iframe.style.border = "1px solid rgba(255,255,255,.10)";
iframe.style.borderRadius = "12px";
iframe.style.background = "rgba(255,255,255,.02)";

addToInjected(markSuspicious(iframe, "iframe without sandbox"));
});

// 5) style attribute containing url(...)
document.getElementById("btnStyleUrl").addEventListener("click", () => {
const d = document.createElement("div");
d.textContent = "Sponsored banner (demo) — style url(...)";
d.setAttribute(
    "style",
    "padding:10px;border-radius:14px;border:1px solid rgba(255,255,255,.10);" +
    "background-image:url(data:image/gif;base64,R0lGODlhAQABAAAAACw=);" // harmless, still matches url(
);

addToInjected(markSuspicious(d, "style contains url(...)"));
});

// Clear injected section
document.getElementById("btnClear").addEventListener("click", () => {
// remove everything except the header text lines at top
const keep = Array.from(injectedArea.childNodes).slice(0, 4);
injectedArea.innerHTML = "";
keep.forEach(n => injectedArea.appendChild(n));
});

// Stress
document.getElementById("btnStress").addEventListener("click", () => {
const frag = document.createDocumentFragment();
for (let i = 0; i < 100; i++) {
    const div = document.createElement("div");
    div.textContent = "Live comment #" + (i + 1);
    frag.appendChild(div);
}
injectedArea.appendChild(frag);
});
