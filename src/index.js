import "dotenv/config";
import express from "ultimate-express";
import { connectDB, getDB } from "./services/db.js";
import { startWSServer } from "./ws-server.js";
import { registerAuthRoutes } from "./routes/auth.routes.js";
import { registerClientsRoutes } from "./routes/clients.routes.js";
import { registerEndpointsRoutes } from "./routes/endpoints.routes.js";
import { registerAuditRoutes } from "./routes/audit.routes.js";
import { registerAdminsRoutes } from "./routes/admins.routes.js";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT_HTTP = Number(process.env.PORT_HTTP) || 3000;
const PORT_WS = Number(process.env.PORT_WS) || 3001;
const PUBLIC = path.join(__dirname, "..", "public");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(PUBLIC));

registerAuthRoutes(app);
registerClientsRoutes(app);
registerEndpointsRoutes(app);
registerAuditRoutes(app);
registerAdminsRoutes(app);

app.get("/", (_req, res) => res.redirect("/dashboard/clients"));

async function main() {
  await connectDB();
  app.listen(PORT_HTTP || 3000, () => console.log(`[http] :${PORT_HTTP}`));
  startWSServer(PORT_WS || 3001);

  async function purgeExpired() {
    try {
      const db = getDB();
      const r = await db.collection("certificates").deleteMany({
        expiresAt: { $lte: new Date() },
      });
      if (r.deletedCount) console.log(`[cleanup] purged ${r.deletedCount} expired cert(s)`);
    } catch {}
  }
  purgeExpired();
  setInterval(purgeExpired, 60_000);
}

main().catch((err) => { console.error(err); process.exit(1); });
