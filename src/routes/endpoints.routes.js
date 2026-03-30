import { ObjectId } from "mongodb";
import crypto from "node:crypto";
import { getDB } from "../db.js";
import { pageAuth } from "../auth.js";
import { render } from "../render.js";

function generateTargetId() {
  return crypto.randomBytes(8).toString("base64url");
}

export function registerEndpointsRoutes(app) {
  // Dashboard page
  app.get("/dashboard/endpoints", pageAuth, async (req, res) => {
    const db = getDB();
    const endpoints = await db.collection("endpoints").find({ userId: req.userId }).toArray();
    render(res, "dashboard/endpoints", { user: req.user, tab: "endpoints", endpoints });
  });

  // Create endpoint (form POST)
  app.post("/dashboard/endpoints", pageAuth, async (req, res) => {
    try {
      const { name, host, port } = req.body;
      if (!name || !host || !port) return res.redirect("/dashboard/endpoints");
      const db = getDB();
      await db.collection("endpoints").insertOne({
        userId: req.userId, name, host, port: Number(port),
        targetId: generateTargetId(), createdAt: new Date(),
      });
    } catch { /* duplicate or error */ }
    res.redirect("/dashboard/endpoints");
  });

  // Delete endpoint
  app.post("/dashboard/endpoints/:id/delete", pageAuth, async (req, res) => {
    const db = getDB();
    await db.collection("endpoints").deleteOne({
      _id: new ObjectId(req.params.id), userId: req.userId,
    });
    res.redirect("/dashboard/endpoints");
  });
}
