import { ObjectId } from "mongodb";
import { getDB } from "../db.js";
import { pageAuth, authMiddleware } from "../auth.js";
import { generateClientCert, generateP12 } from "../ca.js";
import { render } from "../render.js";

export function registerUsersRoutes(app) {
  // SSR page
  app.get("/dashboard/users", pageAuth, async (req, res) => {
    const db = getDB();
    const [tunnelUsers, endpoints] = await Promise.all([
      db.collection("tunnel_users").find().sort({ name: 1 }).toArray(),
      db.collection("endpoints").find().toArray(),
    ]);
    render(res, "dashboard/users", {
      user: req.user, tab: "users", tunnelUsers, endpoints,
      clientScript: "/js/users.js",
    });
  });

  // --- Tunnel users CRUD (JSON) ---
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

  // --- Certs (per tunnel user) ---
  app.get("/api/tunnel-users/:id/certs", authMiddleware, async (req, res) => {
    const db = getDB();
    const certs = await db.collection("certificates")
      .find({ tunnelUserId: req.params.id })
      .project({ clientCert: 0, keyPem: 0 })
      .toArray();
    // Enrich with endpoint info
    const epIds = certs.map(c => c.endpointId).filter(Boolean);
    const endpoints = epIds.length
      ? await db.collection("endpoints").find({ _id: { $in: epIds.map(id => new ObjectId(id)) } }).toArray()
      : [];
    const epMap = Object.fromEntries(endpoints.map(ep => [String(ep._id), ep]));
    const enriched = certs.map(c => ({
      ...c,
      endpoint: c.endpointId ? epMap[String(c.endpointId)] || null : null,
    }));
    res.json(enriched);
  });

  // Generate new cert for a user + endpoint
  app.post("/api/tunnel-users/:id/certs", authMiddleware, async (req, res) => {
    try {
      const { name, endpointId, durationDays, uses } = req.body;
      if (!name || !endpointId) return res.status(400).json({ error: "name and endpointId required" });

      const days = Number(durationDays) || 365;
      const maxUses = Number(uses) || 0; // 0 = unlimited
      const db = getDB();
      const endpoint = await db.collection("endpoints").findOne({ _id: new ObjectId(endpointId) });
      if (!endpoint) return res.status(404).json({ error: "endpoint not found" });

      const result = generateClientCert(name, days);

      const doc = {
        tunnelUserId: req.params.id,
        endpointId: new ObjectId(endpointId),
        name,
        fingerprint: result.fingerprint,
        clientCert: result.certPem,
        keyPem: result.keyPem,
        uses: maxUses,
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + days * 24 * 60 * 60 * 1000),
      };

      const r = await db.collection("certificates").insertOne(doc);

      // Auto-create access window if not exists
      await db.collection("access_windows").findOneAndUpdate(
        { tunnelUserId: req.params.id, endpointId: new ObjectId(endpointId) },
        { $setOnInsert: { tunnelUserId: req.params.id, endpointId: new ObjectId(endpointId), from: new Date(), until: new Date(), active: false, createdAt: new Date() } },
        { upsert: true }
      );

      res.json({
        _id: r.insertedId, name, fingerprint: result.fingerprint,
        endpoint,
      });
    } catch (e) {
      if (e.code === 11000) return res.status(409).json({ error: "duplicate" });
      console.error(e);
      res.status(400).json({ error: "error generating cert" });
    }
  });

  // Download .p12 bundle (cert + key + CA, password-protected)
  app.post("/api/certs/:id/p12", authMiddleware, async (req, res) => {
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: "password required" });

    const db = getDB();
    const cert = await db.collection("certificates").findOne({ _id: new ObjectId(req.params.id) });
    if (!cert || !cert.keyPem) return res.status(404).json({ error: "not found" });

    try {
      const p12 = generateP12(cert.clientCert, cert.keyPem, password);
      const filename = `${cert.name.replace(/[^a-zA-Z0-9._-]/g, "_")}.p12`;
      res.setHeader("Content-Type", "application/x-pkcs12");
      res.setHeader("Content-Disposition", `attachment; filename=${filename}`);
      res.send(p12);
    } catch (e) {
      console.error("p12 error:", e.message);
      res.status(500).json({ error: "p12 generation failed" });
    }
  });

  // Update cert name
  app.put("/api/certs/:id", authMiddleware, async (req, res) => {
    try {
      const { name } = req.body;
      const db = getDB();
      const update = {};
      if (name) update.name = name;
      if (!Object.keys(update).length) return res.status(400).json({ error: "nothing to update" });
      const r = await db.collection("certificates").findOneAndUpdate(
        { _id: new ObjectId(req.params.id) },
        { $set: update },
        { returnDocument: "after", projection: { clientCert: 0, keyPem: 0 } }
      );
      if (!r) return res.status(404).json({ error: "not found" });
      res.json(r);
    } catch (e) {
      res.status(400).json({ error: "error" });
    }
  });

  app.delete("/api/certs/:id", authMiddleware, async (req, res) => {
    const db = getDB();
    await db.collection("certificates").deleteOne({ _id: new ObjectId(req.params.id) });
    res.json({ ok: true });
  });

  // --- Access windows (per tunnel user) ---
  app.get("/api/tunnel-users/:id/access", authMiddleware, async (req, res) => {
    const db = getDB();
    const windows = await db.collection("access_windows")
      .find({ tunnelUserId: req.params.id }).toArray();
    res.json(windows);
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
        {
          $set: { tunnelUserId, endpointId: new ObjectId(endpointId), from: now, until, active },
          $setOnInsert: { createdAt: now },
        },
        { upsert: true, returnDocument: "after" }
      );
      res.json(r);
    } catch (e) {
      res.status(500).json({ error: "error" });
    }
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
    const result = await db.collection("access_windows").deleteMany({
      tunnelUserId, endpointId: new ObjectId(endpointId),
    });
    res.json({ ok: true, deleted: result.deletedCount });
  });
}
