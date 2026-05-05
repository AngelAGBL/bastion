import { ObjectId } from "mongodb";
import crypto from "node:crypto";
import { getDB } from "../services/db.js";
import { pageAuth, authMiddleware } from "../services/auth.js";
import { generateClientCert, generateP12 } from "../services/ca.js";
import { render } from "../utils/render.js";
import { getAllEpClients } from "../services/ep-clients.js";
import bus from "../services/events.js";

const BASE32 = "abcdefghijklmnopqrstuvwxyz234567";
function generateTargetId() {
  const bytes = crypto.randomBytes(10);
  let id = "", bits = 0, val = 0;
  for (const b of bytes) { val = (val << 8) | b; bits += 8; while (bits >= 5) { bits -= 5; id += BASE32[(val >> bits) & 0x1f]; } }
  if (bits > 0) id += BASE32[(val << (5 - bits)) & 0x1f];
  return id;
}

export function registerEndpointsRoutes(app) {
  // SSE for endpoint status changes
  app.get("/api/endpoints/events", authMiddleware, (req, res) => {
    res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", "Connection": "keep-alive" });
    res.write(":\n\n");
    const handler = (data) => res.write(`data: ${JSON.stringify(data)}\n\n`);
    bus.on("ep:status", handler);
    req.on("close", () => bus.off("ep:status", handler));
  });

  // Get online status of all ep-clients
  app.get("/api/endpoints/status", authMiddleware, (req, res) => {
    res.json(getAllEpClients());
  });

  app.get("/dashboard/endpoints", pageAuth, async (req, res) => {
    const db = getDB();
    const endpoints = await db.collection("endpoints").find().toArray();
    const epClients = getAllEpClients();
    render(res, "dashboard/endpoints", { user: req.user, tab: "endpoints", endpoints, epClients });
  });

  app.post("/dashboard/endpoints", pageAuth, async (req, res) => {
    try {
      const { name, host, port, protocol } = req.body;
      if (!name || !host || !port) return res.redirect("/dashboard/endpoints");
      const db = getDB();
      await db.collection("endpoints").insertOne({
        name, host, port: Number(port),
        protocol: protocol === "udp" ? "udp" : "tcp",
        targetId: generateTargetId(), createdAt: new Date(),
      });
    } catch {}
    res.redirect("/dashboard/endpoints");
  });

  app.put("/api/endpoints/:id", authMiddleware, async (req, res) => {
    try {
      const { name, host, port, protocol } = req.body;
      const update = {};
      if (name) update.name = name;
      if (host) update.host = host;
      if (port) update.port = Number(port);
      if (protocol === "tcp" || protocol === "udp") update.protocol = protocol;
      if (!Object.keys(update).length) return res.status(400).json({ error: "nothing to update" });
      const db = getDB();
      const r = await db.collection("endpoints").findOneAndUpdate({ _id: new ObjectId(req.params.id) }, { $set: update }, { returnDocument: "after" });
      if (!r) return res.status(404).json({ error: "not found" });
      res.json(r);
    } catch { res.status(500).json({ error: "error" }); }
  });

  app.post("/dashboard/endpoints/:id/delete", pageAuth, async (req, res) => {
    const db = getDB();
    await db.collection("endpoints").deleteOne({ _id: new ObjectId(req.params.id) });
    await db.collection("access_windows").deleteMany({ endpointId: new ObjectId(req.params.id) });
    res.redirect("/dashboard/endpoints");
  });

  app.get("/api/endpoints", authMiddleware, async (req, res) => {
    const db = getDB();
    res.json(await db.collection("endpoints").find().toArray());
  });

  // --- Endpoint Clients (reverse tunnel) ---

  // Create ep-client: creates an endpoint + cert in one step
  app.post("/api/ep-clients", authMiddleware, async (req, res) => {
    try {
      const { name } = req.body;
      if (!name) return res.status(400).json({ error: "name required" });

      const db = getDB();

      // Create the endpoint (virtual — no real host/port, traffic goes through ep-client)
      const ep = await db.collection("endpoints").insertOne({
        name,
        host: "ep-client",
        port: 0,
        protocol: "tcp",
        virtual: true,
        targetId: generateTargetId(),
        createdAt: new Date(),
      });

      // Generate a cert linked to this endpoint (no expiry, no uses limit)
      const result = generateClientCert(name, 3650);
      await db.collection("certificates").insertOne({
        tunnelUserId: null, // ep-client certs don't belong to a tunnel user
        endpointId: ep.insertedId,
        name: `ep:${name}`,
        fingerprint: result.fingerprint,
        clientCert: result.certPem,
        keyPem: result.keyPem,
        isEpClient: true,
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 3650 * 24 * 60 * 60 * 1000),
      });

      res.json({ _id: ep.insertedId, name, certId: result.fingerprint });
    } catch (e) {
      if (e.code === 11000) return res.status(409).json({ error: "duplicate" });
      console.error(e);
      res.status(500).json({ error: "error creating ep-client" });
    }
  });

  // Download P12 for an ep-client endpoint
  app.post("/api/ep-clients/:id/p12", authMiddleware, async (req, res) => {
    const { password } = req.body;
    const db = getDB();
    const cert = await db.collection("certificates").findOne({
      endpointId: new ObjectId(req.params.id),
      isEpClient: true,
    });
    if (!cert || !cert.keyPem) return res.status(404).json({ error: "not found" });
    try {
      const p12 = generateP12(cert.clientCert, cert.keyPem, password || "");
      const filename = `${cert.name.replace(/[^a-zA-Z0-9._-]/g, "_")}.p12`;
      res.setHeader("Content-Type", "application/x-pkcs12");
      res.setHeader("Content-Disposition", `attachment; filename=${filename}`);
      res.send(p12);
    } catch (e) {
      res.status(500).json({ error: "p12 generation failed" });
    }
  });
}
