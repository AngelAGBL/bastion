import { ObjectId } from "mongodb";
import { getDB } from "../services/db.js";
import { pageAuth, authMiddleware } from "../services/auth.js";
import { render } from "../utils/render.js";

const LIMIT = 100;

export function registerAuditRoutes(app) {
  app.get("/dashboard/audit", pageAuth, async (req, res) => {
    const db = getDB();
    const query = req.query || {};
    const filter = buildFilter(query);
    const logs = await db.collection("audit_logs").find(filter).project({ rawHex: 0 }).sort({ ts: -1 }).limit(LIMIT).toArray();
    const [certs, endpoints, tunnelUsers] = await Promise.all([
      db.collection("certificates").find().project({ clientCert: 0, keyPem: 0 }).toArray(),
      db.collection("endpoints").find().toArray(),
      db.collection("tunnel_users").find().sort({ name: 1 }).toArray(),
    ]);
    const tuMap = Object.fromEntries(tunnelUsers.map(tu => [String(tu._id), tu.name]));
    for (const l of logs) { if (!l.userName && l.userId) l.userName = tuMap[String(l.userId)] || null; }
    if (query.fmt === "json") return res.json(logs);
    render(res, "dashboard/audit", { user: req.user, tab: "audit", logs, certs, endpoints, tunnelUsers, query, limit: LIMIT, clientScript: "/js/audit.js" });
  });

  app.get("/api/audit/:id/raw", authMiddleware, async (req, res) => {
    const db = getDB();
    const log = await db.collection("audit_logs").findOne({ _id: new ObjectId(req.params.id) });
    if (!log) return res.status(404).json({ error: "not found" });
    const raw = log.rawHex ? Buffer.from(log.rawHex, "hex").toString("utf-8").replace(/[\x00-\x08\x0E-\x1F]/g, "�") : log.preview || "";
    res.json({ raw, hex: log.rawHex || "", bytes: log.bytes });
  });
}

function buildFilter(query) {
  const filter = {};
  if (query.certId) { try { filter.certId = new ObjectId(query.certId); } catch {} }
  if (query.endpointId) { try { filter.endpointId = new ObjectId(query.endpointId); } catch {} }
  if (query.userId) filter.userId = query.userId;
  if (query.direction === "upload" || query.direction === "download") filter.direction = query.direction;
  if (query.before) filter.ts = { $lt: new Date(query.before) };
  if (query.after) filter.ts = { ...(filter.ts || {}), $gt: new Date(query.after) };
  return filter;
}
