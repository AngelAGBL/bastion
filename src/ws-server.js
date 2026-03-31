import crypto from "node:crypto";
import net from "node:net";
import fs from "node:fs";
import path from "node:path";
import uWS from "uWebSockets.js";
import { ensureCA, generateServerCert, getCACertPath } from "./ca.js";
import { getDB } from "./db.js";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PREVIEW_MAX = 256;

export async function startWSServer(port) {
  ensureCA();
  const serverTls = generateServerCert();

  // Write server cert/key to temp files for uWS
  const dataDir = path.join(__dirname, "..", "data", "ca");
  const srvKeyPath = path.join(dataDir, "srv-key.pem");
  const srvCertPath = path.join(dataDir, "srv-cert.pem");
  fs.writeFileSync(srvKeyPath, serverTls.key);
  fs.writeFileSync(srvCertPath, serverTls.cert);

  const caCertPem = fs.readFileSync(getCACertPath(), "utf-8");
  const caPublicKey = crypto.createPublicKey(caCertPem);

  const app = uWS.SSLApp({
    key_file_name: srvKeyPath,
    cert_file_name: srvCertPath,
    ca_file_name: getCACertPath(),
  });

  app.ws("/*", {
    maxPayloadLength: 16 * 1024 * 1024,
    idleTimeout: 120,

    upgrade: async (res, req, context) => {
      const targetId = req.getHeader("x-target");
      const secKey = req.getHeader("sec-websocket-key");
      const secProto = req.getHeader("sec-websocket-protocol");
      const secExt = req.getHeader("sec-websocket-extensions");

      let aborted = false;
      res.onAborted(() => { aborted = true; });

      // Get client certificate
      let clientCertDer;
      try {
        clientCertDer = res.getX509Certificate();
      } catch {
        if (!aborted) res.cork(() => res.writeStatus("404 Not Found").end());
        return;
      }

      if (!clientCertDer || !targetId) {
        if (!aborted) res.cork(() => res.writeStatus("404 Not Found").end());
        return;
      }

      try {
        // Verify client cert was signed by our CA
        const x509 = new crypto.X509Certificate(clientCertDer);
        if (!x509.verify(caPublicKey)) {
          if (!aborted) res.cork(() => res.writeStatus("404 Not Found").end());
          return;
        }

        // Compute fingerprint from DER
        const derBuf = Buffer.isBuffer(clientCertDer) ? clientCertDer
          : clientCertDer instanceof ArrayBuffer ? Buffer.from(clientCertDer)
          : Buffer.from(x509.raw);
        const fingerprint = crypto.createHash("sha256").update(derBuf).digest("hex");

        const db = getDB();
        const cert = await db.collection("certificates").findOne({ fingerprint });
        if (!cert) { if (!aborted) res.cork(() => res.writeStatus("404 Not Found").end()); return; }

        const endpoint = await db.collection("endpoints").findOne({ targetId });
        if (!endpoint) { if (!aborted) res.cork(() => res.writeStatus("404 Not Found").end()); return; }

        // Check access window — lookup by tunnelUserId + endpointId
        const now = new Date();
        const window = await db.collection("access_windows").findOne({
          tunnelUserId: cert.tunnelUserId,
          endpointId: endpoint._id,
          active: true,
          from: { $lte: now },
          until: { $gte: now },
        });
        if (!window) { if (!aborted) res.cork(() => res.writeStatus("404 Not Found").end()); return; }

        if (!aborted) {
          res.cork(() => {
            res.upgrade({ cert, endpoint }, secKey, secProto, secExt, context);
          });
        }
      } catch {
        if (!aborted) res.cork(() => res.writeStatus("404 Not Found").end());
      }
    },

    open: (ws) => {
      const { cert, endpoint } = ws.getUserData();
      const tcp = net.createConnection({ host: endpoint.host, port: endpoint.port });

      tcp.on("data", (data) => {
        try { ws.send(data, true); } catch {}
        logTraffic(cert, endpoint, "download", data);
      });
      tcp.on("close", () => { try { ws.close(); } catch {} });
      tcp.on("error", () => { try { ws.close(); } catch {} });

      ws._tcp = tcp;
    },

    message: (ws, message) => {
      const { cert, endpoint } = ws.getUserData();
      const buf = Buffer.from(message);
      if (ws._tcp && !ws._tcp.destroyed) ws._tcp.write(buf);
      logTraffic(cert, endpoint, "upload", buf);
    },

    close: (ws) => {
      if (ws._tcp) ws._tcp.destroy();
    },
  });

  app.listen(port, (sock) => {
    if (sock) console.log(`[ws] mTLS tunnel (uWS SSLApp) on :${port}`);
    else console.error("[ws] failed to listen on port", port);
  });
}

function makePreview(buf) {
  const str = buf.toString("utf-8", 0, Math.min(buf.length, PREVIEW_MAX));
  if (/[\x00-\x08\x0E-\x1F]/.test(str.slice(0, 64))) {
    return buf.toString("hex", 0, Math.min(buf.length, 64)) + (buf.length > 64 ? "…" : "");
  }
  return str + (buf.length > PREVIEW_MAX ? "…" : "");
}

function logTraffic(cert, endpoint, direction, data) {
  const db = getDB();
  db.collection("audit_logs").insertOne({
    userId: cert.tunnelUserId,
    certId: cert._id,
    certName: cert.name,
    fingerprint: cert.fingerprint,
    endpointId: endpoint._id,
    endpointName: endpoint.name,
    targetHost: endpoint.host,
    targetPort: endpoint.port,
    direction,
    bytes: data.length,
    preview: makePreview(data),
    ts: new Date(),
  }).catch(() => {});
}
