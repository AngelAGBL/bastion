const api = async (url, opts = {}) => {
  const res = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "error");
  return data;
};
function esc(s) { const d = document.createElement("div"); d.textContent = s || ""; return d.innerHTML; }

const _endpoints = JSON.parse(document.getElementById("endpoints-data")?.textContent || "[]");
const DURATIONS = [
  { label: "5 min", ms: 5*60000 }, { label: "10 min", ms: 10*60000 },
  { label: "30 min", ms: 30*60000 }, { label: "1 hora", ms: 3600000 },
  { label: "2 horas", ms: 7200000 }, { label: "4 horas", ms: 14400000 },
  { label: "8 horas", ms: 28800000 }, { label: "1 día", ms: 86400000 },
];

// --- Modals ---
function closeModal(id) { document.getElementById(id).classList.add("hidden"); }
document.querySelectorAll(".modal-overlay").forEach(el => {
  el.addEventListener("click", e => { if (e.target === el) el.classList.add("hidden"); });
});

// --- Search ---
function filterUsers(q) {
  const lower = q.toLowerCase();
  document.querySelectorAll(".user-card").forEach(c => {
    c.style.display = c.dataset.name.includes(lower) ? "" : "none";
  });
}

// --- Sub-tabs ---
function showSub(btn, panel, uid) {
  btn.closest(".sub-tabs").querySelectorAll(".btn").forEach(b => {
    b.classList.remove("btn-primary"); b.classList.add("btn-ghost");
  });
  btn.classList.remove("btn-ghost"); btn.classList.add("btn-primary");
  btn.closest(".user-card").querySelectorAll(".sub-panel").forEach(el => el.classList.add("hidden"));
  document.getElementById(`${panel}-${uid}`).classList.remove("hidden");
  if (panel === "certs") loadCerts(uid); else loadAccess(uid);
}

// --- Users ---
async function createUser() {
  const input = document.getElementById("new-user-name");
  const name = input.value.trim();
  if (!name) return input.focus();
  try { await api("/api/tunnel-users", { method: "POST", body: { name } }); input.value = ""; location.reload(); }
  catch (e) { alert(e.message); }
}
document.getElementById("new-user-name")?.addEventListener("keydown", e => { if (e.key === "Enter") createUser(); });

async function deleteUser(uid) {
  if (!confirm("¿Eliminar usuario y todos sus datos?")) return;
  await api(`/api/tunnel-users/${uid}`, { method: "DELETE" });
  document.querySelector(`[data-uid="${uid}"]`).remove();
}

// --- Certs ---
async function loadCerts(uid) {
  const certs = await api(`/api/tunnel-users/${uid}/certs`);
  const el = document.getElementById(`cert-list-${uid}`);
  if (!certs.length) { el.innerHTML = '<p style="color:var(--muted);font-size:.85rem">Sin certificados</p>'; return; }
  el.innerHTML = certs.map(c => `
    <div class="card" style="padding:.5rem" id="cert-${c._id}">
      <div class="row">
        <strong class="grow">${esc(c.name)}</strong>
        <a href="/api/certs/${c._id}/download" class="btn btn-ghost btn-sm" download>⬇</a>
        <button class="btn btn-ghost btn-sm" onclick="openEditCert('${c._id}','${esc(c.name)}','${uid}')">✎</button>
        <button class="btn btn-danger btn-sm" onclick="deleteCert('${c._id}','${uid}')">×</button>
      </div>
      <div class="mono" style="font-size:.7rem">${c.fingerprint}</div>
    </div>`).join("");
}

let _signUid = null;
function openSignCsr(uid) {
  _signUid = uid;
  document.getElementById("modal-sign-uid").value = uid;
  document.getElementById("modal-sign-name").value = "";
  document.getElementById("modal-sign-csr").value = "";
  document.getElementById("modal-sign").classList.remove("hidden");
}
async function submitSignCsr() {
  const uid = document.getElementById("modal-sign-uid").value;
  const name = document.getElementById("modal-sign-name").value.trim();
  const csr = document.getElementById("modal-sign-csr").value.trim();
  if (!name || !csr) return alert("Nombre y CSR requeridos");
  try {
    await api(`/api/tunnel-users/${uid}/certs`, { method: "POST", body: { name, csr } });
    closeModal("modal-sign");
    loadCerts(uid);
  } catch (e) { alert(e.message); }
}

let _editUid = null;
function openEditCert(certId, name, uid) {
  _editUid = uid;
  document.getElementById("modal-edit-cert-id").value = certId;
  document.getElementById("modal-edit-name").value = name;
  document.getElementById("modal-edit-csr").value = "";
  document.getElementById("modal-edit").classList.remove("hidden");
}
async function saveEditCert() {
  const certId = document.getElementById("modal-edit-cert-id").value;
  const name = document.getElementById("modal-edit-name").value.trim();
  const csr = document.getElementById("modal-edit-csr").value.trim();
  const body = {};
  if (name) body.name = name;
  if (csr) body.csr = csr;
  try {
    await api(`/api/certs/${certId}`, { method: "PUT", body });
    closeModal("modal-edit");
    if (_editUid) loadCerts(_editUid);
  } catch (e) { alert(e.message); }
}

async function deleteCert(certId, uid) {
  if (!confirm("¿Eliminar certificado?")) return;
  await api(`/api/certs/${certId}`, { method: "DELETE" });
  loadCerts(uid);
}

// --- Access / Endpoints ---
function timeLeft(until) {
  const diff = new Date(until).getTime() - Date.now();
  if (diff <= 0) return null;
  const h = Math.floor(diff / 3600000);
  const m = Math.floor((diff % 3600000) / 60000);
  const s = Math.floor((diff % 60000) / 1000);
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

let _activeAccessUid = null;

function renderAccessCards(uid, windows) {
  const el = document.getElementById(`access-list-${uid}`);
  const durOpts = DURATIONS.map(d => `<option value="${d.ms}">${d.label}</option>`).join("");

  const assignedEpIds = new Set(windows.map(w => String(w.endpointId)));
  const assignedEps = _endpoints.filter(ep => assignedEpIds.has(String(ep._id)));
  const unassignedEps = _endpoints.filter(ep => !assignedEpIds.has(String(ep._id)));

  // Add endpoint selector (no duration — just assign it)
  let addHtml = "";
  if (unassignedEps.length) {
    const opts = unassignedEps.map(ep =>
      `<option value="${ep._id}">${esc(ep.name)} (${ep.host}:${ep.port})</option>`
    ).join("");
    addHtml = `
    <div class="row mb">
      <select id="add-ep-${uid}" class="grow"><option value="">Agregar endpoint...</option>${opts}</select>
      <button class="btn btn-primary btn-sm" onclick="addEndpoint('${uid}')">+ Agregar</button>
    </div>`;
  }

  let cardsHtml = "";
  if (!assignedEps.length) {
    cardsHtml = '<p style="color:var(--muted);font-size:.85rem">Sin endpoints asignados</p>';
  } else {
    cardsHtml = '<div class="ep-grid">' + assignedEps.map(ep => {
      const epWindows = windows.filter(w => String(w.endpointId) === String(ep._id));
      const running = epWindows.some(w => w.active && new Date(w.until).getTime() > Date.now());
      const best = epWindows.sort((a, b) => new Date(b.until) - new Date(a.until))[0];
      const tl = running ? timeLeft(best.until) : null;
      const borderClass = running ? " ep-active" : "";

      return `
      <div class="card ep-card${borderClass}" style="padding:.6rem">
        <div class="row">
          <strong class="grow">${esc(ep.name)}</strong>
          ${tl ? `<span class="time-left" data-until="${best.until}">${tl}</span>` : ""}
        </div>
        <div class="mono mb" style="font-size:.7rem">${ep.host}:${ep.port} · ${ep.targetId}</div>
        <div class="row">
          ${running ? `
            <button class="btn btn-danger btn-sm" onclick="deactivateAccess('${uid}','${ep._id}')">Desactivar</button>
          ` : `
            <select id="dur-${ep._id}-${uid}" style="width:auto">${durOpts}</select>
            <button class="btn btn-primary btn-sm" onclick="activateAccess('${uid}','${ep._id}')">Activar</button>
          `}
          <button class="btn btn-ghost btn-sm" onclick="revokeAccess('${uid}','${ep._id}')">Revocar</button>
        </div>
      </div>`;
    }).join("") + '</div>';
  }

  el.innerHTML = addHtml + cardsHtml;
}

async function loadAccess(uid) {
  _activeAccessUid = uid;
  const windows = await api(`/api/tunnel-users/${uid}/access`);
  renderAccessCards(uid, windows);
}

// Add endpoint to user (inactive, no timer)
async function addEndpoint(uid) {
  const sel = document.getElementById(`add-ep-${uid}`);
  if (!sel.value) return;
  try {
    await api("/api/access", {
      method: "POST",
      body: { tunnelUserId: uid, endpointId: sel.value },
    });
    loadAccess(uid);
  } catch (e) { alert(e.message); }
}

async function activateAccess(uid, epId) {
  const sel = document.getElementById(`dur-${epId}-${uid}`);
  const durationMs = Number(sel.value);
  try {
    await api("/api/access", { method: "POST", body: { tunnelUserId: uid, endpointId: epId, durationMs } });
    loadAccess(uid);
  } catch (e) { alert(e.message); }
}

async function deactivateAccess(uid, epId) {
  await api("/api/access/deactivate", {
    method: "POST",
    body: { tunnelUserId: uid, endpointId: epId },
  });
  loadAccess(uid);
}

async function revokeAccess(uid, epId) {
  if (!confirm("¿Revocar acceso? El endpoint desaparecerá del usuario.")) return;
  await api("/api/access/revoke", {
    method: "POST",
    body: { tunnelUserId: uid, endpointId: epId },
  });
  loadAccess(uid);
}

// Countdown + auto-refresh on expiry
setInterval(() => {
  let needsRefresh = false;
  document.querySelectorAll(".time-left[data-until]").forEach(el => {
    const tl = timeLeft(el.dataset.until);
    if (tl) el.textContent = tl;
    else needsRefresh = true;
  });
  if (needsRefresh && _activeAccessUid) loadAccess(_activeAccessUid);
}, 1000);

document.addEventListener("DOMContentLoaded", () => {
  const first = document.querySelector(".user-card");
  if (first) loadCerts(first.dataset.uid);
});
