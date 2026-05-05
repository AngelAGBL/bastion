/**
 * Registry of connected endpoint clients (reverse tunnels).
 * An endpoint client connects via WS to /ep-register, and the server
 * routes tunnel traffic through it instead of direct TCP.
 */

const registry = new Map(); // endpointId → { ws, name, connectedAt }

export function registerEpClient(endpointId, ws, name) {
  registry.set(endpointId, { ws, name, connectedAt: new Date() });
}

export function unregisterEpClient(endpointId) {
  registry.delete(endpointId);
}

export function getEpClient(endpointId) {
  return registry.get(endpointId) || null;
}

export function isEpClientOnline(endpointId) {
  return registry.has(endpointId);
}

export function getAllEpClients() {
  const result = {};
  for (const [id, info] of registry) {
    result[id] = { name: info.name, connectedAt: info.connectedAt };
  }
  return result;
}
