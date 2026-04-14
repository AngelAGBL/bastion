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
  const limitInInput = document.getElementById(`cert-limitin-${uid}`);
  const limitOutInput = document.getElementById(`cert-limitout-${uid}`);
  const name = nameInput.value.trim();
  const endpointId = epSelect.value;
  const durationDays = Number(durSelect.value);
  const limitInKiB = Number(limitInInput.value) || 0;
  const limitOutKiB = Number(limitOutInput.value) || 0;
  if (!name) return nameInput.focus();
  if (!endpointId) return alert("Seleccione un endpoint");
  try {
    await api(`/api/tunnel-users/${uid}/certs`, { method: "POST", body: { name, endpointId, durationDays, limitInKiB, limitOutKiB } });
    nameInput.value = "";
    epSelect.value = "";
    limitInInput.value = "10";
    limitOutInput.value = "50";
    loadUserData(uid);
  } catch (e) { alert(e.message); }
}

function openEditCert(certId, name, limitIn, limitOut, uid) {
  document.getElementById("modal-edit-cert-id").value = certId;
  document.getElementById("modal-edit-uid").value = uid;
  document.getElementById("modal-edit-name").value = name;
  document.getElementById("modal-edit-limitin").value = limitIn;
  document.getElementById("modal-edit-limitout").value = limitOut;
  document.getElementById("modal-edit").classList.remove("hidden");
}
async function saveEditCert() {
  const certId = document.getElementById("modal-edit-cert-id").value;
  const uid = document.getElementById("modal-edit-uid").value;
  const name = document.getElementById("modal-edit-name").value.trim();
  const limitInKiB = Number(document.getElementById("modal-edit-limitin").value);
  const limitOutKiB = Number(document.getElementById("modal-edit-limitout").value);
  if (!name) return;
  try {
    await api(`/api/certs/${certId}`, { method: "PUT", body: { name, limitInKiB, limitOutKiB } });
    closeModal("modal-edit");
    loadUserData(uid);
  } catch (e) { alert(e.message); }
}

async function resetBw(certId, uid) {
  if (!confirm("¿Resetear bandwidth a 0?")) return;
  await api(`/api/certs/${certId}/reset-bw`, { method: "POST" });
  loadUserData(uid);
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
    el.innerHTML = '<p class="empty-msg">Sin certificados</p>';
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

    const epName = ep ? esc(ep.name) : '<span class="ep-deleted">Endpoint eliminado</span>';
    const epProto = ep ? (ep.protocol || 'tcp').toUpperCase() : '';
    const epAddr = ep ? `${epProto} ${esc(ep.host)}:${ep.port}` : '—';

    html += `<div class="card ep-card-inner${borderClass}">`;
    html += `<div class="row mb">`;
    html += `<strong class="grow">${epName}</strong>`;
    if (tl) html += `<span class="time-left" data-until="${w.until}">${tl}</span>`;
    html += `</div>`;
    html += `<div class="mono mb ep-addr">${epAddr}</div>`;

    // Access controls
    if (w) {
      html += `<div class="row mb">`;
      if (running) {
        html += `<button class="btn btn-danger btn-sm" onclick="deactivateAccess('${uid}','${epId}')">Desactivar</button>`;
      } else {
        html += `<select id="dur-${epId}-${uid}" class="dur-select">${durOpts}</select>`;
        html += `<button class="btn btn-primary btn-sm" onclick="activateAccess('${uid}','${epId}')">Activar</button>`;
      }
      html += `</div>`;
    }

    // Certs inside this endpoint
    html += '<div class="cert-grid">';
    for (const c of epCerts) {
      const isExpired = c.expiresAt && new Date(c.expiresAt) < new Date();
      const certTl = !isExpired && c.expiresAt ? timeLeft(c.expiresAt) : null;
      const expClass = isExpired ? 'cert-ttl-expired' : 'cert-ttl-ok';
      const expLabel = isExpired ? 'EXPIRADO' : (certTl || '—');
      const inLimit = c.limitInKiB || 0;
      const outLimit = c.limitOutKiB || 0;
      const usedIn = c.usedInBytes || 0;
      const usedOut = c.usedOutBytes || 0;
      const inLabel = inLimit > 0 ? `↑${(usedIn/1024).toFixed(1)}/${inLimit}KiB` : '↑∞';
      const outLabel = outLimit > 0 ? `↓${(usedOut/1024).toFixed(1)}/${outLimit}KiB` : '↓∞';
      const inExceeded = inLimit > 0 && usedIn >= inLimit * 1024;
      const outExceeded = outLimit > 0 && usedOut >= outLimit * 1024;
      const inClass = inExceeded ? 'cert-bw-over' : 'cert-bw-ok';
      const outClass = outExceeded ? 'cert-bw-over' : 'cert-bw-ok';

      html += `<div class="card cert-card cert-card-inner" data-cert-id="${c._id}">`;
      html += `<div class="row"><strong class="grow cert-name">${esc(c.name)}</strong>`;
      html += `<button class="btn btn-danger btn-sm" onclick="deleteCert('${c._id}','${uid}')">×</button></div>`;
      html += `<div class="row cert-info-row">`;
      html += `<span class="${inClass}">${inLabel}</span> <span class="${outClass}">${outLabel}</span>`;
      html += `<div class="grow"></div>`;
      html += `<span class="cert-ttl ${expClass}" data-expires="${c.expiresAt || ''}">${expLabel}</span>`;
      html += `</div>`;
      html += `<div class="row mt cert-actions">`;
      html += `<button class="btn btn-ghost btn-sm" onclick="downloadP12('${c._id}')">⬇ .p12</button>`;
      html += `<button class="btn btn-ghost btn-sm" onclick="resetBw('${c._id}','${uid}')" title="Resetear bandwidth">↺</button>`;
      html += `<button class="btn btn-ghost btn-sm" onclick="openAudit('${c._id}','${esc(c.name)}')" title="Auditoría">📋</button>`;
      html += `<button class="btn btn-ghost btn-sm" onclick="openEditCert('${c._id}','${esc(c.name)}',${inLimit},${outLimit},'${uid}')">✎</button>`;
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

// --- Audit per cert ---
let _auditEvtSource = null;
let _auditCertId = null;

// Control Pictures U+2400–U+2421 for codes 0x00–0x21
const CTRL_PICS = "␀␁␂␃␄␅␆␇␈␉␊␋␌␍␎␏␐␑␒␓␔␕␖␗␘␙␚␛␜␝␞␟␠␡";

function applyBitOffset(hexStr, offset) {
  if (!offset || !hexStr) return hexStr;
  const bytes = hexStr.match(/.{1,2}/g).map(b => parseInt(b, 16));
  const shifted = new Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    const cur = bytes[i];
    const prev = i > 0 ? bytes[i - 1] : 0;
    shifted[i] = ((prev << (8 - offset)) | (cur >> offset)) & 0xFF;
  }
  return shifted.map(b => b.toString(16).padStart(2, "0")).join("");
}

function hexToDisplay(hex) {
  if (!hex) return "";
  const bytes = hex.match(/.{1,2}/g).map(b => parseInt(b, 16));
  let out = "";
  for (const b of bytes) {
    if (b <= 0x21) {
      out += CTRL_PICS[b] || "�";
    } else if (b === 0x7F) {
      out += "␡";
    } else if (b >= 0x20 && b < 0x7F) {
      out += String.fromCharCode(b);
    } else {
      // Try UTF-8 decode for this byte — fallback to ?
      try {
        const decoded = new TextDecoder("utf-8", { fatal: true }).decode(new Uint8Array([b]));
        out += decoded;
      } catch {
        out += "�";
      }
    }
  }
  return out;
}

function hexToDisplayFull(hex) {
  if (!hex) return "";
  try {
    const bytes = new Uint8Array(hex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
    const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    let out = "";
    for (const ch of text) {
      const code = ch.codePointAt(0);
      if (code === 0x0A || code === 0x0D || code === 0x09 || code === 0x20) {
        // Space, newline, carriage return, tab — print as-is
        out += ch;
      } else if (code <= 0x20) {
        out += CTRL_PICS[code] || "�";
      } else if (code === 0x7F) {
        out += "␡";
      } else if (code === 0xFFFD) {
        out += "�";
      } else {
        out += ch;
      }
    }
    return out;
  } catch { return hex; }
}

function getAuditOffset() {
  try {
    const sel = document.getElementById("audit-offset");
    return sel ? Number(sel.value) || 0 : 0;
  } catch { return 0; }
}

function renderLogRow(log) {
  const d = new Date(log.ts);
  const date = d.toLocaleDateString("es");
  const time = d.toLocaleTimeString("es");
  const dir = log.direction === "upload" ? "↑" : "↓";
  const dirClass = log.direction === "upload" ? "dir-up" : "dir-down";
  const offset = getAuditOffset();
  const hex = applyBitOffset(log.rawHex, offset);
  const content = hexToDisplayFull(hex).replace(/</g, "&lt;");
  return `<div class="audit-row">
    <div class="audit-meta">
      <div>${esc(date)}</div>
      <div>${esc(time)}</div>
      <div class="${dirClass}">${dir} ${log.bytes}</div>
    </div>
    <div class="audit-content">${content}</div>
  </div>`;
}

let _auditLogs = []; // cached for re-render on offset change

async function openAudit(certId, certName) {
  _auditCertId = certId;
  const titleEl = document.getElementById("modal-audit-title");
  const offsetEl = document.getElementById("audit-offset");
  const logsEl = document.getElementById("audit-logs");
  const modalEl = document.getElementById("modal-audit");
  if (!titleEl || !logsEl || !modalEl) return;
  titleEl.textContent = "Auditoría: " + certName;
  if (offsetEl) offsetEl.value = "0";
  logsEl.innerHTML = "Cargando...";
  modalEl.classList.remove("hidden");

  if (_auditEvtSource) { _auditEvtSource.close(); _auditEvtSource = null; }

  try {
    const logs = await api(`/api/certs/${certId}/audit`);
    _auditLogs = logs.reverse();
    logsEl.innerHTML = _auditLogs.length ? _auditLogs.map(renderLogRow).join("") : '<span class="empty-msg">Sin registros</span>';
    logsEl.scrollTop = logsEl.scrollHeight;
  } catch { logsEl.innerHTML = "Error cargando logs"; }

  _auditEvtSource = new EventSource(`/api/certs/${certId}/audit/events`);
  _auditEvtSource.onmessage = (e) => {
    try {
      const log = JSON.parse(e.data);
      _auditLogs.push(log);
      const placeholder = logsEl.querySelector("span");
      if (placeholder && placeholder.textContent === "Sin registros") logsEl.innerHTML = "";
      logsEl.insertAdjacentHTML("beforeend", renderLogRow(log));
      logsEl.scrollTop = logsEl.scrollHeight;
    } catch {}
  };
}

function reloadAudit() {
  const logsEl = document.getElementById("audit-logs");
  if (!_auditLogs.length) return;
  logsEl.innerHTML = _auditLogs.map(renderLogRow).join("");
  logsEl.scrollTop = logsEl.scrollHeight;
}

function closeAudit() {
  document.getElementById("modal-audit").classList.add("hidden");
  if (_auditEvtSource) { _auditEvtSource.close(); _auditEvtSource = null; }
  _auditLogs = [];
  _auditCertId = null;
}

// Close audit modal on overlay click
document.getElementById("modal-audit")?.addEventListener("click", e => {
  if (e.target.id === "modal-audit") closeAudit();
});

// Countdown + auto-refresh on expiry (every 1s for timers)
setInterval(() => {
  let needsRefresh = false;
  document.querySelectorAll(".time-left[data-until]").forEach(el => {
    const tl = timeLeft(el.dataset.until);
    if (tl) el.textContent = tl;
    else needsRefresh = true;
  });
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

  // SSE: real-time bandwidth updates (debounced to avoid flooding)
  const evtSource = new EventSource("/api/clients/events");
  let _sseTimer = null;
  evtSource.onmessage = () => {
    if (_sseTimer) return;
    _sseTimer = setTimeout(() => {
      _sseTimer = null;
      for (const uid of _activeUids) loadUserData(uid);
    }, 2000);
  };
});
