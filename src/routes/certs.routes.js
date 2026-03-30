import { ObjectId } from "mongodb";
import { getDB } from "../db.js";
import { pageAuth, authMiddleware } from "../auth.js";
import { getCACert, fingerprintFromPEM } from "../ca.js";
import { render } from "../render.js";

export function registerCertsRoutes(app) {
  // Public API — download CA cert
  app.get("/api/certs/ca", (_req, res) => {
    res.setHeader("Content-Type", "application/x-pem-file");
    res.send(getCACert());
  });

  // Dashboard page
  app.get("/dashboard/certs", pageAuth, async (req, res) => {
    const db = getDB();
    const [certs, endpoints] = await Promise.all([
      db.collection("certificates").find({ userId: req.userId }).project({ clientCert: 0 }).toArray(),
      db.collection("endpoints").find({ userId: req.userId }).toArray(),
    ]);
    render(res, "dashboard/certs", { user: req.user, tab: "certs", certs, endpoints });
  });

  // Register client cert (form POST — user pastes their public PEM)
  app.post("/dashboard/certs", pageAuth, async (req, res) => {
    const { name, publicPem } = req.body;
    let error = null;

    if (!name || !publicPem) {
      error = "Nombre y certificado público son requeridos";
    }

    let fingerprint;
    if (!error) {
      try {
        fingerprint = fingerprintFromPEM(publicPem.trim());
      } catch {
        error = "El certificado PEM no es válido";
      }
    }

    if (!error) {
      try {
        const db = getDB();
        await db.collection("certificates").insertOne({
          userId: req.userId,
          name,
          fingerprint,
          clientCert: publicPem.trim(),
          allowedEndpoints: [],
          createdAt: new Date(),
        });
      } catch (e) {
        error = e.code === 11000 ? "Este certificado ya está registrado" : "Error al guardar";
      }
    }

    const db = getDB();
    const [certs, endpoints] = await Promise.all([
      db.collection("certificates").find({ userId: req.userId }).project({ clientCert: 0 }).toArray(),
      db.collection("endpoints").find({ userId: req.userId }).toArray(),
    ]);
    render(res, "dashboard/certs", { user: req.user, tab: "certs", certs, endpoints, error });
  });

  // Delete cert
  app.post("/dashboard/certs/:id/delete", pageAuth, async (req, res) => {
    const db = getDB();
    await db.collection("certificates").deleteOne({
      _id: new ObjectId(req.params.id), userId: req.userId,
    });
    res.redirect("/dashboard/certs");
  });

  // Grant endpoint to cert
  app.post("/dashboard/certs/:id/grant-endpoint", pageAuth, async (req, res) => {
    const { targetId } = req.body;
    if (targetId) {
      const db = getDB();
      await db.collection("certificates").updateOne(
        { _id: new ObjectId(req.params.id), userId: req.userId },
        { $addToSet: { allowedEndpoints: targetId } }
      );
    }
    res.redirect("/dashboard/certs");
  });

  // Revoke endpoint from cert
  app.post("/dashboard/certs/:id/revoke-endpoint", pageAuth, async (req, res) => {
    const { targetId } = req.body;
    if (targetId) {
      const db = getDB();
      await db.collection("certificates").updateOne(
        { _id: new ObjectId(req.params.id), userId: req.userId },
        { $pull: { allowedEndpoints: targetId } }
      );
    }
    res.redirect("/dashboard/certs");
  });

  // JSON API
  app.get("/api/certs", authMiddleware, async (req, res) => {
    const db = getDB();
    const certs = await db.collection("certificates")
      .find({ userId: req.userId }).project({ clientCert: 0 }).toArray();
    res.json(certs);
  });
}
