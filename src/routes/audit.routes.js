import { ObjectId } from "mongodb";
import { getDB } from "../db.js";
import { pageAuth } from "../auth.js";
import { render } from "../render.js";

const LIMIT = 100;

export function registerAuditRoutes(app) {
  app.get("/dashboard/audit", pageAuth, async (req, res) => {
    const db = getDB();
    const query = req.query || {};
    const filter = buildFilter(req.userId, query);

    const logs = await db.collection("audit_logs")
      .find(filter)
      .sort({ ts: -1 })
      .limit(LIMIT)
      .toArray();

    const [certs, endpoints] = await Promise.all([
      db.collection("certificates").find({ userId: req.userId }).project({ clientCert: 0 }).toArray(),
      db.collection("endpoints").find({ userId: req.userId }).toArray(),
    ]);

    // JSON response for live polling
    if (query.fmt === "json") {
      return res.json(logs);
    }

    render(res, "dashboard/audit", {
      user: req.user, tab: "audit", logs, certs, endpoints,
      query, limit: LIMIT, clientScript: "/js/audit.js",
    });
  });
}

function buildFilter(userId, query) {
  const filter = { userId };

  if (query.certId) {
    try { filter.certId = new ObjectId(query.certId); } catch {}
  }
  if (query.endpointId) {
    try { filter.endpointId = new ObjectId(query.endpointId); } catch {}
  }
  if (query.direction === "upload" || query.direction === "download") {
    filter.direction = query.direction;
  }
  if (query.before) {
    filter.ts = { $lt: new Date(query.before) };
  }
  if (query.after) {
    filter.ts = { ...(filter.ts || {}), $gt: new Date(query.after) };
  }

  return filter;
}
