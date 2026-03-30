(function () {
  const btn = document.getElementById("btn-live");
  const tbody = document.querySelector(".log-table tbody");
  let live = false;
  let timer = null;
  let lastTs = null;

  // Grab the latest timestamp from existing rows
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
          <td>${esc(log.certName || log.fingerprint?.slice(0, 12) + "…")}</td>
          <td>${esc(log.endpointName || log.targetHost + ":" + log.targetPort)}</td>
          <td class="${log.direction === "upload" ? "dir-up" : "dir-down"}">${log.direction === "upload" ? "↑" : "↓"}</td>
          <td class="log-size">${log.bytes}</td>
          <td class="log-preview">${esc(log.preview)}</td>`;
        // Remove "sin registros" placeholder
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
})();
