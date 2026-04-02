(function () {
  const tbody = document.querySelector(".log-table tbody");

  function esc(s) {
    const d = document.createElement("div");
    d.textContent = s || "";
    return d.innerHTML;
  }

  function addRow(log) {
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
  }

  // SSE: real-time audit logs
  const evtSource = new EventSource("/api/audit/events");
  evtSource.onmessage = (e) => {
    try {
      addRow(JSON.parse(e.data));
    } catch {}
  };

  // --- Raw content modal ---
  let _rawId = null;
  let _rawData = null;
  let _showHex = false;
  const modal = document.getElementById("modal-raw");
  const pre = document.getElementById("raw-content");
  const btnHex = document.getElementById("btn-toggle-hex");
  const offsetSel = document.getElementById("raw-offset");

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

  window.reloadRaw = async function () {
    if (!_rawId) return;
    await window.viewRaw(_rawId);
  };

  window.viewRaw = async function (id) {
    _rawId = id;
    _rawData = null;
    _showHex = false;
    btnHex.textContent = "Hex";
    pre.textContent = "Cargando...";
    modal.classList.remove("hidden");
    try {
      const offset = offsetSel.value || "0";
      const res = await fetch("/api/audit/" + id + "/raw?offset=" + offset);
      if (!res.ok) throw new Error();
      _rawData = await res.json();
      renderRaw();
    } catch {
      pre.textContent = "Error al cargar contenido.";
    }
  };
})();
