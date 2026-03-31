import { ObjectId } from "mongodb";
import { getDB } from "../db.js";
import { pageAuth, authMiddleware } from "../auth.js";
import { getCACert, signCSR } from "../ca.js";
import { render } from "../render.js";

export function registerUsersRoutes(app) {
  // Download CA
  app.get("/api/ca.pem", (_req, res) => {
    res.setHeader("Content-Type", "application/x-pem-file");
    res.setHeader("Content-Disposition", "attachment; filename=bastion-ca.pem");
    res.send(getCACert());
  });

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
      .project({ clientCert: 0 })
      .toArray();
    res.json(certs);
  });

  app.post("/api/tunnel-users/:id/certs", authMiddleware, async (req, res) => {
    try {
      const { name, csr } = req.body;
      if (!name || !csr) return res.status(400).json({ error: "name and csr required" });
      const { cert, fingerprint } = signCSR(csr.trim());
      const db = getDB();
      const r = await db.collection("certificates").insertOne({
        tunnelUserId: req.params.id,
        name, fingerprint, clientCert: cert,
        createdAt: new Date(),
      });
      res.json({ _id: r.insertedId, name, fingerprint, cert });
    } catch (e) {
      if (e.code === 11000) return res.status(409).json({ error: "duplicate" });
      res.status(400).json({ error: "invalid CSR" });
    }
  });

  // Download individual cert PEM
  app.get("/api/certs/:id/download", authMiddleware, async (req, res) => {
    const db = getDB();
    const cert = await db.collection("certificates").findOne({ _id: new ObjectId(req.params.id) });
    if (!cert || !cert.clientCert) return res.status(404).json({ error: "not found" });
    res.setHeader("Content-Type", "application/x-pem-file");
    res.setHeader("Content-Disposition", `attachment; filename=${cert.name.replace(/[^a-zA-Z0-9._-]/g, "_")}.crt.pem`);
    res.send(cert.clientCert);
  });

  // Update cert (name and/or re-sign new CSR)
  app.put("/api/certs/:id", authMiddleware, async (req, res) => {
    try {
      const { name, csr } = req.body;
      const db = getDB();
      const update = {};
      if (name) update.name = name;
      if (csr) {
        const result = signCSR(csr.trim());
        update.clientCert = result.cert;
        update.fingerprint = result.fingerprint;
      }
      if (!Object.keys(update).length) return res.status(400).json({ error: "nothing to update" });
      const r = await db.collection("certificates").findOneAndUpdate(
        { _id: new ObjectId(req.params.id) },
        { $set: update },
        { returnDocument: "after", projection: { clientCert: 0 } }
      );
      if (!r) return res.status(404).json({ error: "not found" });
      res.json(r);
    } catch (e) {
      if (e.code === 11000) return res.status(409).json({ error: "duplicate fingerprint" });
      res.status(400).json({ error: "invalid CSR or data" });
    }
  });

  app.delete("/api/certs/:id", authMiddleware, async (req, res) => {
    const db = getDB();
    const cert = await db.collection("certificates").findOne({ _id: new ObjectId(req.params.id) });
    if (cert) await db.collection("access_windows").deleteMany({ certId: cert._id });
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
      // If durationMs provided, activate with timer. Otherwise create inactive.
      const active = !!durationMs;
      const until = durationMs ? new Date(now.getTime() + Number(durationMs)) : now;

      // Upsert a single window per tunnelUserId+endpointId
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

  // Deactivate all windows for a user+endpoint
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

  // Revoke = delete ALL windows for a user+endpoint
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
