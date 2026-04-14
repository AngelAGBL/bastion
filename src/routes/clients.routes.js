import { ObjectId } from "mongodb";
import { getDB } from "../services/db.js";
import { pageAuth, authMiddleware } from "../services/auth.js";
import { generateClientCert, generateP12 } from "../services/ca.js";
import { render } from "../utils/render.js";
import bus from "../services/events.js";

export function registerClientsRoutes(app) {
  // SSE stream for real-time cert use updates (panel only)
  app.get("/api/clients/events", authMiddleware, (req, res) => {
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive",
    });
    res.write(":\n\n");
    const handler = (data) => {
      res.write(`data: ${JSON.stringify(data)}\n\n`);
    };
    bus.on("cert:bandwidth", handler);
    req.on("close", () => { bus.off("cert:bandwidth", handler); });
  });

  app.get("/dashboard/clients", pageAuth, async (req, res) => {
    const db = getDB();
    const [tunnelUsers, endpoints] = await Promise.all([
      db.collection("tunnel_users").find().sort({ name: 1 }).toArray(),
      db.collection("endpoints").find().toArray(),
    ]);
    render(res, "dashboard/clients", {
      user: req.user, tab: "clients", tunnelUsers, endpoints,
      clientScript: "/js/clients.js",
    });
  });

  // --- Tunnel users CRUD ---
  app.post("/api/tunnel-users", authMiddleware, async (req, res) => {
    try {
      const { name } = req.body;
      if (!name) return res.status(400).json({ error: "name required" });
      const db = getDB();
      const r = await db.collection("tunnel_users").insertOne({ name, createdAt: new Date() });
      res.json({ _id: r.insertedId, name });
    } catch (e) {
      res.status(e.code === 11000 ? 409 : 500).json({ error: e.code === 11000 ? "exists" : "error" });
    }
  });

  app.delete("/api/tunnel-users/:id", authMiddleware, async (req, res) => {
    const db = getDB();
    const uid = req.params.id;
    await db.collection("certificates").deleteMany({ tunnelUserId: uid });
    await db.collection("access_windows").deleteMany({ tunnelUserId: uid });
    await db.collection("tunnel_users").deleteOne({ _id: new ObjectId(uid) });
    res.json({ ok: true });
  });

  app.get("/api/tunnel-users", authMiddleware, async (req, res) => {
    const db = getDB();
    const q = req.query?.q || "";
    const filter = q ? { name: { $regex: q, $options: "i" } } : {};
    const users = await db.collection("tunnel_users").find(filter).sort({ name: 1 }).toArray();
    res.json(users);
  });

  // --- Certs ---
  app.get("/api/tunnel-users/:id/certs", authMiddleware, async (req, res) => {
    const db = getDB();
    const certs = await db.collection("certificates")
      .find({ tunnelUserId: req.params.id })
      .project({ clientCert: 0, keyPem: 0 })
      .toArray();
    const epIds = certs.map(c => c.endpointId).filter(Boolean);
    const endpoints = epIds.length
      ? await db.collection("endpoints").find({ _id: { $in: epIds.map(id => new ObjectId(id)) } }).toArray()
      : [];
    const epMap = Object.fromEntries(endpoints.map(ep => [String(ep._id), ep]));
    res.json(certs.map(c => ({ ...c, endpoint: c.endpointId ? epMap[String(c.endpointId)] || null : null })));
  });

  app.post("/api/tunnel-users/:id/certs", authMiddleware, async (req, res) => {
    try {
      const { name, endpointId, durationDays, limitInKiB, limitOutKiB } = req.body;
      if (!name || !endpointId) return res.status(400).json({ error: "name and endpointId required" });
      const days = Number(durationDays) || 365;
      const inKiB = Number(limitInKiB) || 0;
      const outKiB = Number(limitOutKiB) || 0;
      const db = getDB();
      const endpoint = await db.collection("endpoints").findOne({ _id: new ObjectId(endpointId) });
      if (!endpoint) return res.status(404).json({ error: "endpoint not found" });
      const result = generateClientCert(name, days);
      const r = await db.collection("certificates").insertOne({
        tunnelUserId: req.params.id, endpointId: new ObjectId(endpointId),
        name, fingerprint: result.fingerprint, clientCert: result.certPem, keyPem: result.keyPem,
        limitInKiB: inKiB, limitOutKiB: outKiB, usedInBytes: 0, usedOutBytes: 0,
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + days * 24 * 60 * 60 * 1000),
      });
      await db.collection("access_windows").findOneAndUpdate(
        { tunnelUserId: req.params.id, endpointId: new ObjectId(endpointId) },
        { $setOnInsert: { tunnelUserId: req.params.id, endpointId: new ObjectId(endpointId), from: new Date(), until: new Date(), active: false, createdAt: new Date() } },
        { upsert: true }
      );
      res.json({ _id: r.insertedId, name, fingerprint: result.fingerprint, endpoint });
    } catch (e) {
      if (e.code === 11000) return res.status(409).json({ error: "duplicate" });
      console.error(e);
      res.status(400).json({ error: "error generating cert" });
    }
  });

  app.post("/api/certs/:id/p12", authMiddleware, async (req, res) => {
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: "password required" });
    const db = getDB();
    const cert = await db.collection("certificates").findOne({ _id: new ObjectId(req.params.id) });
    if (!cert || !cert.keyPem) return res.status(404).json({ error: "not found" });
    try {
      const p12 = generateP12(cert.clientCert, cert.keyPem, password);
      res.setHeader("Content-Type", "application/x-pkcs12");
      res.setHeader("Content-Disposition", `attachment; filename=${cert.name.replace(/[^a-zA-Z0-9._-]/g, "_")}.p12`);
      res.send(p12);
    } catch (e) { res.status(500).json({ error: "p12 generation failed" }); }
  });

  app.put("/api/certs/:id", authMiddleware, async (req, res) => {
    try {
      const { name, limitInKiB, limitOutKiB } = req.body;
      const update = {};
      if (name) update.name = name;
      if (limitInKiB !== undefined) update.limitInKiB = Number(limitInKiB);
      if (limitOutKiB !== undefined) update.limitOutKiB = Number(limitOutKiB);
      if (!Object.keys(update).length) return res.status(400).json({ error: "nothing to update" });
      const db = getDB();
      const r = await db.collection("certificates").findOneAndUpdate(
        { _id: new ObjectId(req.params.id) }, { $set: update },
        { returnDocument: "after", projection: { clientCert: 0, keyPem: 0 } }
      );
      if (!r) return res.status(404).json({ error: "not found" });
      res.json(r);
    } catch { res.status(400).json({ error: "error" }); }
  });

  // Reset bandwidth usage to 0
  app.post("/api/certs/:id/reset-bw", authMiddleware, async (req, res) => {
    const db = getDB();
    const r = await db.collection("certificates").findOneAndUpdate(
      { _id: new ObjectId(req.params.id) },
      { $set: { usedInBytes: 0, usedOutBytes: 0 } },
      { returnDocument: "after", projection: { clientCert: 0, keyPem: 0 } }
    );
    if (!r) return res.status(404).json({ error: "not found" });
    res.json(r);
  });

  // --- Audit per cert ---
  app.get("/api/certs/:id/audit", authMiddleware, async (req, res) => {
    const db = getDB();
    const logs = await db.collection("audit_logs")
      .find({ certId: new ObjectId(req.params.id) })
      .sort({ ts: -1 })
      .limit(200)
      .toArray();
    res.json(logs);
  });

  // SSE: real-time audit logs filtered by certId
  app.get("/api/certs/:id/audit/events", authMiddleware, (req, res) => {
    const certId = req.params.id;
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive",
    });
    res.write(":\n\n");
    const handler = (data) => {
      if (String(data.certId) === certId) {
        res.write(`data: ${JSON.stringify(data)}\n\n`);
      }
    };
    bus.on("audit:log", handler);
    req.on("close", () => bus.off("audit:log", handler));
  });

  app.delete("/api/certs/:id", authMiddleware, async (req, res) => {
    const db = getDB();
    await db.collection("certificates").deleteOne({ _id: new ObjectId(req.params.id) });
    res.json({ ok: true });
  });

  // --- Access windows ---
  app.get("/api/tunnel-users/:id/access", authMiddleware, async (req, res) => {
    const db = getDB();
    res.json(await db.collection("access_windows").find({ tunnelUserId: req.params.id }).toArray());
  });

  app.post("/api/access", authMiddleware, async (req, res) => {
    try {
      const { tunnelUserId, endpointId, durationMs } = req.body;
      if (!tunnelUserId || !endpointId) return res.status(400).json({ error: "missing" });
      const db = getDB();
      const now = new Date();
      const active = !!durationMs;
      const until = durationMs ? new Date(now.getTime() + Number(durationMs)) : now;
      const r = await db.collection("access_windows").findOneAndUpdate(
        { tunnelUserId, endpointId: new ObjectId(endpointId) },
        { $set: { tunnelUserId, endpointId: new ObjectId(endpointId), from: now, until, active }, $setOnInsert: { createdAt: now } },
        { upsert: true, returnDocument: "after" }
      );
      res.json(r);
    } catch { res.status(500).json({ error: "error" }); }
  });

  app.post("/api/access/deactivate", authMiddleware, async (req, res) => {
    const { tunnelUserId, endpointId } = req.body;
    if (!tunnelUserId || !endpointId) return res.status(400).json({ error: "missing" });
    const db = getDB();
    await db.collection("access_windows").updateMany(
      { tunnelUserId, endpointId: new ObjectId(endpointId) },
      { $set: { active: false, until: new Date() } }
    );
    res.json({ ok: true });
  });

  app.post("/api/access/revoke", authMiddleware, async (req, res) => {
    const { tunnelUserId, endpointId } = req.body;
    if (!tunnelUserId || !endpointId) return res.status(400).json({ error: "missing" });
    const db = getDB();
    const result = await db.collection("access_windows").deleteMany({ tunnelUserId, endpointId: new ObjectId(endpointId) });
    res.json({ ok: true, deleted: result.deletedCount });
  });
}
