import { ObjectId } from "mongodb";
import crypto from "node:crypto";
import { getDB } from "../services/db.js";
import { pageAuth, authMiddleware } from "../services/auth.js";
import { render } from "../utils/render.js";

const BASE32 = "abcdefghijklmnopqrstuvwxyz234567";
function generateTargetId() {
  const bytes = crypto.randomBytes(10);
  let id = "", bits = 0, val = 0;
  for (const b of bytes) { val = (val << 8) | b; bits += 8; while (bits >= 5) { bits -= 5; id += BASE32[(val >> bits) & 0x1f]; } }
  if (bits > 0) id += BASE32[(val << (5 - bits)) & 0x1f];
  return id;
}

export function registerEndpointsRoutes(app) {
  app.get("/dashboard/endpoints", pageAuth, async (req, res) => {
    const db = getDB();
    const endpoints = await db.collection("endpoints").find().toArray();
    render(res, "dashboard/endpoints", { user: req.user, tab: "endpoints", endpoints });
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
}
