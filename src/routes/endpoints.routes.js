import { ObjectId } from "mongodb";
import crypto from "node:crypto";
import { getDB } from "../db.js";
import { pageAuth, authMiddleware } from "../auth.js";
import { render } from "../render.js";

function generateTargetId() {
  return crypto.randomBytes(8).toString("base64url");
}

export function registerEndpointsRoutes(app) {
  // SSR page
  app.get("/dashboard/endpoints", pageAuth, async (req, res) => {
    const db = getDB();
    const endpoints = await db.collection("endpoints").find().toArray();
    render(res, "dashboard/endpoints", { user: req.user, tab: "endpoints", endpoints });
  });

  // Create (form POST)
  app.post("/dashboard/endpoints", pageAuth, async (req, res) => {
    try {
      const { name, host, port } = req.body;
      if (!name || !host || !port) return res.redirect("/dashboard/endpoints");
      const db = getDB();
      await db.collection("endpoints").insertOne({
        name, host, port: Number(port),
        targetId: generateTargetId(), createdAt: new Date(),
      });
    } catch {}
    res.redirect("/dashboard/endpoints");
  });

  // Delete (form POST)
  app.post("/dashboard/endpoints/:id/delete", pageAuth, async (req, res) => {
    const db = getDB();
    await db.collection("endpoints").deleteOne({ _id: new ObjectId(req.params.id) });
    await db.collection("access_windows").deleteMany({ endpointId: new ObjectId(req.params.id) });
    res.redirect("/dashboard/endpoints");
  });

  // JSON API
  app.get("/api/endpoints", authMiddleware, async (req, res) => {
    const db = getDB();
    const endpoints = await db.collection("endpoints").find().toArray();
    res.json(endpoints);
  });
}
