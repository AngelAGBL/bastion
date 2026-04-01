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
const _epMap = Object.fromEntries(_endpoints.map(ep => [String(ep._id), ep]));
const DURATIONS = [
  { label: "5 min", ms: 5*60000 }, { label: "10 min", ms: 10*60000 },
  { label: "30 min", ms: 30*60000 }, { label: "1 hora", ms: 3600000 },
  { label: "2 horas", ms: 7200000 }, { label: "4 horas", ms: 14400000 },
  { label: "8 horas", ms: 28800000 }, { label: "1 día", ms: 86400000 },
];
const durOpts = DURATIONS.map(d => `<option value="${d.ms}">${d.label}</option>`).join("");

function closeModal(id) { document.getElementById(id).classList.add("hidden"); }
document.querySelectorAll(".modal-overlay").forEach(el => {
  el.addEventListener("click", e => { if (e.target === el) el.classList.add("hidden"); });
});

function filterUsers(q) {
  const lower = q.toLowerCase();
  document.querySelectorAll(".user-card").forEach(c => {
    c.style.display = c.dataset.name.includes(lower) ? "" : "none";
  });
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
async function generateCert(uid) {
  const nameInput = document.getElementById(`cert-name-${uid}`);
  const epSelect = document.getElementById(`cert-ep-${uid}`);
  const durSelect = document.getElementById(`cert-dur-${uid}`);
  const usesInput = document.getElementById(`cert-uses-${uid}`);
  const name = nameInput.value.trim();
  const endpointId = epSelect.value;
  const durationDays = Number(durSelect.value);
  const uses = Number(usesInput.value) || 0;
  if (!name) return nameInput.focus();
  if (!endpointId) return alert("Seleccione un endpoint");
  try {
    await api(`/api/tunnel-users/${uid}/certs`, { method: "POST", body: { name, endpointId, durationDays, uses } });
    nameInput.value = "";
    epSelect.value = "";
    usesInput.value = "3";
    loadUserData(uid);
  } catch (e) { alert(e.message); }
}

function openEditCert(certId, name, uid) {
  document.getElementById("modal-edit-cert-id").value = certId;
  document.getElementById("modal-edit-uid").value = uid;
  document.getElementById("modal-edit-name").value = name;
  document.getElementById("modal-edit").classList.remove("hidden");
}
async function saveEditCert() {
  const certId = document.getElementById("modal-edit-cert-id").value;
  const uid = document.getElementById("modal-edit-uid").value;
  const name = document.getElementById("modal-edit-name").value.trim();
  if (!name) return;
  try {
    await api(`/api/certs/${certId}`, { method: "PUT", body: { name } });
    closeModal("modal-edit");
    loadUserData(uid);
  } catch (e) { alert(e.message); }
}

async function deleteCert(certId, uid) {
  if (!confirm("¿Eliminar certificado?")) return;
  await api(`/api/certs/${certId}`, { method: "DELETE" });
  loadUserData(uid);
}

async function downloadP12(certId) {
  const password = prompt("Contraseña para proteger el archivo .p12:");
  if (!password) return;
  try {
    const resp = await fetch(`/api/certs/${certId}/p12`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password }),
    });
    if (!resp.ok) { const e = await resp.json(); throw new Error(e.error); }
    const blob = await resp.blob();
    const cd = resp.headers.get("content-disposition") || "";
    const match = cd.match(/filename=(.+)/);
    const filename = match ? match[1] : "tunnel.p12";
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
  } catch (e) { alert("Error: " + e.message); }
}

// --- Unified load: certs grouped by endpoint + access windows ---
function timeLeft(until) {
  const diff = new Date(until).getTime() - Date.now();
  if (diff <= 0) return null;
  const d = Math.floor(diff / 86400000);
  const h = Math.floor((diff % 86400000) / 3600000);
  const m = Math.floor((diff % 3600000) / 60000);
  const s = Math.floor((diff % 60000) / 1000);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

let _activeUids = new Set();

async function loadUserData(uid) {
  _activeUids.add(uid);
  const [certs, windows] = await Promise.all([
    api(`/api/tunnel-users/${uid}/certs`),
    api(`/api/tunnel-users/${uid}/access`),
  ]);

  const el = document.getElementById(`ep-certs-${uid}`);

  // Group certs by endpointId
  const byEp = {};
  for (const c of certs) {
    const epId = String(c.endpointId);
    if (!byEp[epId]) byEp[epId] = [];
    byEp[epId].push(c);
  }

  const epIds = Object.keys(byEp);
  if (!epIds.length) {
    el.innerHTML = '<p style="color:var(--muted);font-size:.85rem">Sin certificados</p>';
    return;
  }

  const windowMap = {};
  for (const w of windows) windowMap[String(w.endpointId)] = w;

  let html = '<div class="ep-grid-half">';
  for (const epId of epIds) {
    const ep = _epMap[epId];
    const epCerts = byEp[epId];
    const w = windowMap[epId];
    const running = w && w.active && new Date(w.until).getTime() > Date.now();
    const tl = running ? timeLeft(w.until) : null;
    const borderClass = running ? " ep-active" : "";

    const epName = ep ? esc(ep.name) : '<span style="color:var(--danger)">Endpoint eliminado</span>';
    const epAddr = ep ? `${esc(ep.host)}:${ep.port}` : '—';

    html += `<div class="card${borderClass}" style="padding:.75rem;margin-bottom:.5rem">`;
    html += `<div class="row mb">`;
    html += `<strong class="grow">${epName}</strong>`;
    if (tl) html += `<span class="time-left" data-until="${w.until}">${tl}</span>`;
    html += `</div>`;
    html += `<div class="mono mb" style="font-size:.75rem">${epAddr}</div>`;

    // Access controls
    if (w) {
      html += `<div class="row mb">`;
      if (running) {
        html += `<button class="btn btn-danger btn-sm" onclick="deactivateAccess('${uid}','${epId}')">Desactivar</button>`;
      } else {
        html += `<select id="dur-${epId}-${uid}" style="width:auto">${durOpts}</select>`;
        html += `<button class="btn btn-primary btn-sm" onclick="activateAccess('${uid}','${epId}')">Activar</button>`;
      }
      html += `<button class="btn btn-ghost btn-sm" onclick="revokeAccess('${uid}','${epId}')">Revocar</button>`;
      html += `</div>`;
    }

    // Certs inside this endpoint
    html += '<div class="cert-grid">';
    for (const c of epCerts) {
      const isExpired = c.expiresAt && new Date(c.expiresAt) < new Date();
      const certTl = !isExpired && c.expiresAt ? timeLeft(c.expiresAt) : null;
      const expStyle = isExpired ? 'color:var(--danger)' : 'color:var(--muted)';
      const expLabel = isExpired ? 'EXPIRADO' : (certTl || '—');
      const usesLabel = c.uses > 0 ? `${c.uses} usos` : (c.uses === 0 ? '<span style="color:var(--danger)">sin usos</span>' : '∞');

      html += `<div class="card cert-card" style="padding:.5rem;background:var(--bg)">`;
      html += `<div class="row mb"><strong class="grow" style="font-size:.85rem">${esc(c.name)}</strong>`;
      html += `<span style="font-size:.7rem;color:var(--muted);white-space:nowrap">${usesLabel}</span>`;
      html += `<span class="cert-ttl" data-expires="${c.expiresAt || ''}" style="font-size:.7rem;${expStyle};white-space:nowrap">${expLabel}</span></div>`;
      html += `<div class="mono mb" style="font-size:.7rem">${c.fingerprint}</div>`;
      html += `<div class="row" style="gap:.25rem">`;
      html += `<button class="btn btn-ghost btn-sm" onclick="downloadP12('${c._id}')">⬇ .p12</button>`;
      html += `<div class="grow"></div>`;
      html += `<button class="btn btn-ghost btn-sm" onclick="openEditCert('${c._id}','${esc(c.name)}','${uid}')">✎</button>`;
      html += `<button class="btn btn-danger btn-sm" onclick="deleteCert('${c._id}','${uid}')">×</button>`;
      html += `</div></div>`;
    }

    html += '</div>'; // close cert-grid
    html += `</div>`; // close endpoint card
  }

  html += '</div>';
  el.innerHTML = html;
}

// --- Access actions ---
async function activateAccess(uid, epId) {
  const sel = document.getElementById(`dur-${epId}-${uid}`);
  const durationMs = Number(sel.value);
  try {
    await api("/api/access", { method: "POST", body: { tunnelUserId: uid, endpointId: epId, durationMs } });
    loadUserData(uid);
  } catch (e) { alert(e.message); }
}

async function deactivateAccess(uid, epId) {
  await api("/api/access/deactivate", { method: "POST", body: { tunnelUserId: uid, endpointId: epId } });
  loadUserData(uid);
}

async function revokeAccess(uid, epId) {
  if (!confirm("¿Revocar acceso? El endpoint desaparecerá del usuario.")) return;
  await api("/api/access/revoke", { method: "POST", body: { tunnelUserId: uid, endpointId: epId } });
  loadUserData(uid);
}

// Countdown + auto-refresh on expiry
setInterval(() => {
  let needsRefresh = false;
  document.querySelectorAll(".time-left[data-until]").forEach(el => {
    const tl = timeLeft(el.dataset.until);
    if (tl) el.textContent = tl;
    else needsRefresh = true;
  });
  // Update cert TTL counters
  document.querySelectorAll(".cert-ttl[data-expires]").forEach(el => {
    const exp = el.dataset.expires;
    if (!exp) return;
    const tl = timeLeft(exp);
    if (tl) { el.textContent = tl; el.style.color = 'var(--muted)'; }
    else { needsRefresh = true; }
  });
  if (needsRefresh) {
    for (const uid of _activeUids) loadUserData(uid);
  }
}, 1000);

// Load data for all users on page load
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".user-card").forEach(card => {
    loadUserData(card.dataset.uid);
  });
});
