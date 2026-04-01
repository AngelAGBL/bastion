import { ObjectId } from "mongodb";
import { getDB } from "../services/db.js";
import { pageAuth, authMiddleware } from "../services/auth.js";
import { hashPassword } from "../utils/crypto.js";
import { render } from "../utils/render.js";

export function registerAdminsRoutes(app) {
  // SSR page
  app.get("/dashboard/admins", pageAuth, async (req, res) => {
    const db = getDB();
    const admins = await db.collection("users").find({}, { projection: { password: 0 } }).sort({ username: 1 }).toArray();
    render(res, "dashboard/admins", { user: req.user, tab: "admins", admins, clientScript: "/js/admins.js" });
  });

  // Create admin
  app.post("/api/admins", authMiddleware, async (req, res) => {
    try {
      const { username, password } = req.body;
      if (!username || !password) return res.status(400).json({ error: "username and password required" });
      if (password.length < 6) return res.status(400).json({ error: "password too short" });
      const db = getDB();
      const hashed = await hashPassword(password);
      const r = await db.collection("users").insertOne({ username, password: hashed });
      res.json({ _id: r.insertedId, username });
    } catch (e) {
      res.status(e.code === 11000 ? 409 : 500).json({ error: e.code === 11000 ? "username exists" : "error" });
    }
  });

  // Change password
  app.put("/api/admins/:id/password", authMiddleware, async (req, res) => {
    try {
      const { password } = req.body;
      if (!password || password.length < 6) return res.status(400).json({ error: "password too short" });
      const db = getDB();
      const hashed = await hashPassword(password);
      const r = await db.collection("users").findOneAndUpdate(
        { _id: new ObjectId(req.params.id) },
        { $set: { password: hashed } },
        { returnDocument: "after", projection: { password: 0 } }
      );
      if (!r) return res.status(404).json({ error: "not found" });
      res.json(r);
    } catch { res.status(500).json({ error: "error" }); }
  });

  // Delete admin (prevent deleting self)
  app.delete("/api/admins/:id", authMiddleware, async (req, res) => {
    if (req.params.id === req.userId) return res.status(400).json({ error: "cannot delete yourself" });
    const db = getDB();
    const r = await db.collection("users").deleteOne({ _id: new ObjectId(req.params.id) });
    if (!r.deletedCount) return res.status(404).json({ error: "not found" });
    res.json({ ok: true });
  });
}
