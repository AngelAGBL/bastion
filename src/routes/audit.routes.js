import { ObjectId } from "mongodb";
import { getDB } from "../services/db.js";
import { pageAuth, authMiddleware } from "../services/auth.js";
import { render } from "../utils/render.js";
import bus from "../services/events.js";

const LIMIT = 100;

export function registerAuditRoutes(app) {
  // SSE stream for real-time audit logs
  app.get("/api/audit/events", authMiddleware, (req, res) => {
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive",
    });
    res.write(":\n\n");
    const handler = (data) => {
      res.write(`data: ${JSON.stringify(data)}\n\n`);
    };
    bus.on("audit:log", handler);
    req.on("close", () => bus.off("audit:log", handler));
  });

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
    const offset = Math.min(7, Math.max(0, Number(req.query.offset) || 0));
    let hex = log.rawHex || "";
    let rawBuf = hex ? Buffer.from(hex, "hex") : Buffer.alloc(0);
    // Apply bit offset: shift all bytes right by N bits
    if (offset > 0 && rawBuf.length > 0) {
      const shifted = Buffer.alloc(rawBuf.length);
      for (let i = 0; i < rawBuf.length; i++) {
        const cur = rawBuf[i];
        const prev = i > 0 ? rawBuf[i - 1] : 0;
        shifted[i] = ((prev << (8 - offset)) | (cur >> offset)) & 0xFF;
      }
      rawBuf = shifted;
      hex = shifted.toString("hex");
    }
    const raw = rawBuf.toString("utf-8").replace(/[\x00-\x08\x0E-\x1F]/g, "�");
    res.json({ raw, hex, bytes: log.bytes, offset });
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
