/* Sentinel bridge - wires new UI (D:\\hackathon\\index.html build) to real backend.
   - Restores last real scan from localStorage synchronously so patched w8() returns it.
   - Fetches /api/sentinel/latest in background.
   - Intercepts Check project + Upload ZIP buttons to call real backend instead of mock.
*/
(function () {
  var LS_KEY = "sentinel_real_v1";

  function loadCache() {
    try {
      var raw = localStorage.getItem(LS_KEY);
      if (!raw) return null;
      var obj = JSON.parse(raw);
      if (obj && obj.findings && obj.findings.length) return obj;
    } catch (e) {}
    return null;
  }

  var cached = loadCache();
  if (cached) {
    window.__SENTINEL_REAL__ = cached;
  }

  async function refreshLatest() {
    try {
      var r = await fetch("/api/sentinel/latest", { cache: "no-store" });
      var j = await r.json();
      if (j && j.has_data && j.findings && j.findings.length) {
        var obj = { project: j.project, findings: j.findings };
        window.__SENTINEL_REAL__ = obj;
        try { localStorage.setItem(LS_KEY, JSON.stringify(obj)); } catch (e) {}
      } else {
        // Backend empty -> clear any stale cache so no old codebase results linger.
        // Results are shown only after that particular codebase scan completes.
        window.__SENTINEL_REAL__ = null;
        try { localStorage.removeItem(LS_KEY); } catch (e) {}
      }
    } catch (e) {}
  }
  refreshLatest();

  function toast(msg) {
    try {
      var el = document.createElement("div");
      el.textContent = msg;
      el.style.cssText = "position:fixed;bottom:16px;left:50%;transform:translateX(-50%);background:#111827;color:#e5e7eb;border:1px solid #374151;padding:8px 14px;border-radius:8px;font:12px monospace;z-index:9999";
      document.body.appendChild(el);
      setTimeout(function () { el.remove(); }, 4000);
    } catch (e) {}
  }

  async function doGitScan(repoUrl, token) {
    toast("Sentinel backend: cloning practice copy + scanning... (live repo never touched)");
    var r = await fetch("/api/sentinel/scan-git", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repo_url: repoUrl, access_token: token || null })
    });
    var j = await r.json();
    if (j.error) { toast("Scan failed: " + j.error.slice(0, 200)); return null; }
    var obj = { project: j.project, findings: j.findings };
    window.__SENTINEL_REAL__ = obj;
    try { localStorage.setItem(LS_KEY, JSON.stringify(obj)); } catch (e) {}
    toast("Real scan done: " + j.count + " findings via " + (j.source || "backend"));
    return obj;
  }

  async function doZipUpload(file) {
    toast("Sentinel backend: uploading + scanning " + file.name + "...");
    var fd = new FormData();
    fd.append("file", file);
    var r = await fetch("/api/sentinel/upload", { method: "POST", body: fd });
    var j = await r.json();
    if (j.error) { toast("Upload failed: " + String(j.error).slice(0, 200)); return null; }
    var obj = { project: j.project, findings: j.findings };
    window.__SENTINEL_REAL__ = obj;
    try { localStorage.setItem(LS_KEY, JSON.stringify(obj)); } catch (e) {}
    toast("Real scan done: " + j.count + " findings (" + (j.source || "") + ")");
    return obj;
  }

  async function doFolderUpload(fileList) {
    var files = Array.prototype.slice.call(fileList || []);
    if (!files.length) { toast("No folder files selected"); return null; }
    toast("Sentinel backend: uploading folder (" + files.length + " files) + scanning...");
    var fd = new FormData();
    files.forEach(function (f) {
      var rel = f.webkitRelativePath || f.name;
      fd.append("files", f, rel);
    });
    var r = await fetch("/api/sentinel/upload-folder", { method: "POST", body: fd });
    var j = await r.json();
    if (j.error) { toast("Folder upload failed: " + String(j.error).slice(0, 200)); return null; }
    var obj = { project: j.project, findings: j.findings };
    window.__SENTINEL_REAL__ = obj;
    try { localStorage.setItem(LS_KEY, JSON.stringify(obj)); } catch (e) {}
    toast("Real scan done: " + j.count + " findings from folder (" + (j.source || "") + ")");
    return obj;
  }

  function goRisk() {
    if (window.location.pathname !== "/risk") window.location.href = "/risk";
    else window.location.reload();
  }

  function wire() {
    var startBtn = document.querySelector('[data-testid="button-start-scan"]');
    var repoInput = document.querySelector('[data-testid="input-repo"]');
    var zipBtn = document.querySelector('[data-testid="button-upload-zip"]');
    var zipInput = document.querySelector('[data-testid="input-zip"]');

    // Private-repo token field (optional, never stored) - clean row below the main inputs
    if (repoInput && !document.getElementById("sentinel-token-row")) {
      var row = document.createElement("div");
      row.id = "sentinel-token-row";
      row.style.cssText = "display:flex;gap:8px;align-items:center;margin-top:10px;flex-wrap:wrap;";
      var tok = document.createElement("input");
      tok.id = "sentinel-token-input";
      tok.type = "password";
      tok.placeholder = "GitHub token — private repos only (optional)";
      tok.autocomplete = "off";
      tok.className = repoInput.className;
      tok.style.cssText = "height:40px;max-width:320px;flex:1 1 220px;background:#0b1220;border:1px solid #1f2937;border-radius:8px;padding:0 12px;color:#e5e7eb;font-family:monospace;font-size:12px;outline:none;";
      var hint = document.createElement("span");
      hint.textContent = "Public links need no token";
      hint.title = "Private repos: use a fine-grained PAT with Contents:read. The app runs git clone --depth 1 into locked uploads/<id>/repo and scans that copy only. Token is sent once, never stored.";
      hint.style.cssText = "font-size:11px;color:#6b7280;cursor:help;white-space:nowrap;";
      row.appendChild(tok);
      row.appendChild(hint);
      // place row under the button row, not inside the black input box
      var host = repoInput.closest("div.mt-5") || repoInput.parentElement.parentElement || repoInput.parentElement;
      host.appendChild(row);
    }

    if (startBtn && !startBtn.dataset.wired) {
      startBtn.dataset.wired = "1";
      startBtn.addEventListener("click", async function (ev) {
        var url = repoInput && repoInput.value ? repoInput.value.trim() : "";
        if (!url) return; // let mock handle empty
        var tokEl = document.getElementById("sentinel-token-input");
        var tok = tokEl && tokEl.value ? tokEl.value.trim() : null;
        ev.preventDefault(); ev.stopPropagation();
        startBtn.disabled = true;
        try {
          var obj = await doGitScan(url, tok);
          if (obj) goRisk();
        } finally { startBtn.disabled = false; }
      }, true);
    }

    if (zipInput && !zipInput.dataset.wired) {
      zipInput.dataset.wired = "1";
      zipInput.addEventListener("change", async function (ev) {
        var f = ev.target.files && ev.target.files[0];
        if (!f) return;
        ev.preventDefault(); ev.stopPropagation();
        var obj = await doZipUpload(f);
        if (obj) goRisk();
      }, true);
    }

    // Inject "Upload Folder (no zip)" next to Upload ZIP - supports raw codebase folder via webkitdirectory
    var zipBtnEl = document.querySelector('[data-testid="button-upload-zip"]');
    if (zipBtnEl && !document.getElementById("sentinel-folder-input")) {
      var folderInput = document.createElement("input");
      folderInput.type = "file";
      folderInput.id = "sentinel-folder-input";
      folderInput.setAttribute("webkitdirectory", "");
      folderInput.setAttribute("directory", "");
      folderInput.multiple = true;
      folderInput.style.display = "none";
      document.body.appendChild(folderInput);
      var folderBtn = document.createElement("button");
      folderBtn.type = "button";
      folderBtn.id = "sentinel-folder-btn";
      folderBtn.textContent = "Upload Folder";
      folderBtn.className = zipBtnEl.className;
      folderBtn.removeAttribute("style");
      folderBtn.setAttribute("data-testid", "button-upload-folder");
      folderBtn.title = "Select a code folder directly (no zip needed)";
      zipBtnEl.insertAdjacentElement("afterend", folderBtn);
      folderBtn.addEventListener("click", function () { folderInput.click(); });
      folderInput.addEventListener("change", async function (ev) {
        if (!ev.target.files || !ev.target.files.length) return;
        folderBtn.disabled = true;
        try {
          var obj = await doFolderUpload(ev.target.files);
          if (obj) goRisk();
        } finally { folderBtn.disabled = false; ev.target.value = ""; }
      });
    }

    // Subtle footer line under the card (not inside the button row)
    if (!document.getElementById("sentinel-backend-badge")) {
      var badge = document.createElement("div");
      badge.id = "sentinel-backend-badge";
      badge.style.cssText = "font-size:11px;color:#6b7280;margin-top:10px;";
      badge.innerHTML = 'Local scan engine connected · <a href="#" id="sentinel-clear" style="color:#6b7280;text-decoration:underline">clear results</a>';
      var card = (zipBtn && zipBtn.closest("div.mt-5")) || (startBtn && startBtn.parentElement);
      if (card && card.parentElement) card.parentElement.appendChild(badge);
      else if (zipBtn && zipBtn.parentElement) zipBtn.parentElement.appendChild(badge);
      document.addEventListener("click", function (e) {
        if (e.target && e.target.id === "sentinel-clear") {
          e.preventDefault();
          localStorage.removeItem(LS_KEY);
          window.__SENTINEL_REAL__ = null;
          fetch("/api/clear", { method: "POST" }).finally(function () { window.location.reload(); });
        }
      });
    }
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", function () { wire(); setInterval(wire, 1500); });
  else { wire(); setInterval(wire, 1500); }
})();
