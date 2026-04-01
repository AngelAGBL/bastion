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

async function createAdmin() {
  const userInput = document.getElementById("new-admin-user");
  const passInput = document.getElementById("new-admin-pass");
  const username = userInput.value.trim();
  const password = passInput.value;
  if (!username || !password) return alert("Usuario y contraseña requeridos");
  try {
    await api("/api/admins", { method: "POST", body: { username, password } });
    location.reload();
  } catch (e) { alert(e.message); }
}

async function changePassword(id, username) {
  const password = prompt(`Nueva contraseña para ${username}:`);
  if (!password) return;
  try {
    await api(`/api/admins/${id}/password`, { method: "PUT", body: { password } });
    alert("Contraseña actualizada");
  } catch (e) { alert(e.message); }
}

async function deleteAdmin(id, username) {
  if (!confirm(`¿Eliminar administrador ${username}?`)) return;
  try {
    await api(`/api/admins/${id}`, { method: "DELETE" });
    document.querySelector(`[data-aid="${id}"]`).remove();
  } catch (e) { alert(e.message); }
}
