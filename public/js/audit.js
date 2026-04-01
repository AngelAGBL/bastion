(function () {
  const btn = document.getElementById("btn-live");
  const tbody = document.querySelector(".log-table tbody");
  let live = false;
  let timer = null;
  let lastTs = null;

  const rows = tbody.querySelectorAll("tr[data-ts]");
  if (rows.length) lastTs = rows[0].dataset.ts;

  btn.addEventListener("click", () => {
    live = !live;
    btn.textContent = live ? "■ Detener" : "● En vivo";
    btn.style.color = live ? "var(--danger)" : "";
    if (live) poll();
    else clearTimeout(timer);
  });

  async function poll() {
    if (!live) return;
    try {
      const params = new URLSearchParams(location.search);
      if (lastTs) params.set("after", lastTs);
      params.set("fmt", "json");
      const res = await fetch("/dashboard/audit?" + params.toString());
      if (!res.ok) throw new Error();
      const logs = await res.json();
      for (let i = logs.length - 1; i >= 0; i--) {
        const log = logs[i];
        const tr = document.createElement("tr");
        tr.dataset.ts = log.ts;
        tr.innerHTML = `
          <td class="mono">${new Date(log.ts).toLocaleString("es")}</td>
          <td>${esc(log.userName || "—")}</td>
          <td>${esc(log.certName || log.fingerprint?.slice(0, 12) + "…")}</td>
          <td>${esc(log.endpointName || log.targetHost + ":" + log.targetPort)}</td>
          <td class="${log.direction === "upload" ? "dir-up" : "dir-down"}">${log.direction === "upload" ? "↑" : "↓"}</td>
          <td class="log-size">${log.bytes}</td>
          <td class="log-preview">${esc(log.preview)}</td>
          <td><button class="btn btn-ghost btn-sm" onclick="viewRaw('${log._id}')">👁</button></td>`;
        const placeholder = tbody.querySelector("td[colspan]");
        if (placeholder) placeholder.parentElement.remove();
        tbody.prepend(tr);
        lastTs = log.ts;
      }
    } catch { /* ignore */ }
    timer = setTimeout(poll, 2000);
  }

  function esc(s) {
    const d = document.createElement("div");
    d.textContent = s || "";
    return d.innerHTML;
  }

  // --- Raw content modal ---
  let _rawData = null;
  let _showHex = false;
  const modal = document.getElementById("modal-raw");
  const pre = document.getElementById("raw-content");
  const btnHex = document.getElementById("btn-toggle-hex");

  modal.addEventListener("click", e => { if (e.target === modal) modal.classList.add("hidden"); });

  btnHex.addEventListener("click", () => {
    _showHex = !_showHex;
    btnHex.textContent = _showHex ? "Raw" : "Hex";
    renderRaw();
  });

  function renderRaw() {
    if (!_rawData) return;
    pre.textContent = _showHex ? _rawData.hex : _rawData.raw;
  }

  window.viewRaw = async function (id) {
    _rawData = null;
    _showHex = false;
    btnHex.textContent = "Hex";
    pre.textContent = "Cargando...";
    modal.classList.remove("hidden");
    try {
      const res = await fetch("/api/audit/" + id + "/raw");
      if (!res.ok) throw new Error();
      _rawData = await res.json();
      renderRaw();
    } catch {
      pre.textContent = "Error al cargar contenido.";
    }
  };
})();
