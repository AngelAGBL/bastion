import crypto from "node:crypto";
import net from "node:net";
import tls from "node:tls";
import https from "node:https";
import { WebSocketServer } from "ws";
import { ensureCA, generateServerCert, getCACert } from "./ca.js";
import { getDB } from "./db.js";

const PREVIEW_MAX = 256;

function log(...args) {
  const msg = args.map(a => typeof a === "object" ? JSON.stringify(a) : String(a)).join(" ");
  console.log(`[ws ${new Date().toISOString()}] ${msg}`);
}

export async function startWSServer(port) {
  ensureCA();
  const serverTls = generateServerCert();
  const caCertPem = getCACert();

  // HTTPS server with mTLS
  const server = https.createServer({
    key: serverTls.key,
    cert: serverTls.cert,
    ca: [caCertPem],
    requestCert: true,
    rejectUnauthorized: false, // we verify manually
  });

  // Health check endpoint
  server.on("request", (req, res) => {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("bastion-ws alive\n");
  });

  // WebSocket server on top of the HTTPS server
  const wss = new WebSocketServer({ noServer: true, skipUTF8Validation: true });

  server.on("upgrade", async (req, socket, head) => {
    const targetId = req.headers["x-target"];
    log(`upgrade: target=${targetId || "-"}`);

    // Extract client cert from TLS socket
    const tlsSocket = req.socket;
    const peerCert = tlsSocket.getPeerCertificate(true);
    const hasCert = peerCert && peerCert.raw && peerCert.raw.length > 0;

    log(`tls: authorized=${tlsSocket.authorized} hasCert=${hasCert}`);

    if (!hasCert || !targetId) {
      log("REJECT: no cert or no target");
      socket.write("HTTP/1.1 404 Not Found\r\n\r\n");
      socket.destroy();
      return;
    }

    // Verify cert against our CA
    try {
      const x509 = new crypto.X509Certificate(peerCert.raw);
      const caKey = crypto.createPublicKey(caCertPem);
      if (!x509.verify(caKey)) {
        log("REJECT: cert not signed by our CA");
        socket.write("HTTP/1.1 404 Not Found\r\n\r\n");
        socket.destroy();
        return;
      }
    } catch (e) {
      log("REJECT: cert verify error:", e.message);
      socket.write("HTTP/1.1 404 Not Found\r\n\r\n");
      socket.destroy();
      return;
    }

    const fingerprint = crypto.createHash("sha256").update(peerCert.raw).digest("hex");
    log(`cert fp=${fingerprint.slice(0, 16)}…`);

    // DB lookups
    try {
      const db = getDB();

      const cert = await db.collection("certificates").findOne({ fingerprint });
      if (!cert) { log("REJECT: cert not in DB"); socket.write("HTTP/1.1 404 Not Found\r\n\r\n"); socket.destroy(); return; }
      log(`cert: ${cert.name} (user=${cert.tunnelUserId})`);

      const endpoint = await db.collection("endpoints").findOne({ targetId });
      if (!endpoint) { log(`REJECT: target ${targetId} not found`); socket.write("HTTP/1.1 404 Not Found\r\n\r\n"); socket.destroy(); return; }
      log(`endpoint: ${endpoint.name} → ${endpoint.host}:${endpoint.port}`);

      const now = new Date();
      const window = await db.collection("access_windows").findOne({
        tunnelUserId: cert.tunnelUserId,
        endpointId: endpoint._id,
        active: true,
        from: { $lte: now },
        until: { $gte: now },
      });
      if (!window) { log("REJECT: no active window"); socket.write("HTTP/1.1 404 Not Found\r\n\r\n"); socket.destroy(); return; }

      log("ACCESS GRANTED — upgrading WebSocket");

      // Accept the WebSocket upgrade
      wss.handleUpgrade(req, socket, head, (ws) => {
        // Disable mask validation — wstunnel sends unmasked frames for performance
        if (ws._receiver) ws._receiver._isServer = false;

        log(`ws open: ${cert.name} → ${endpoint.host}:${endpoint.port}`);

        // Open TCP to target
        const tcp = net.createConnection({ host: endpoint.host, port: endpoint.port });

        tcp.on("connect", () => {
          log(`tcp connected ${endpoint.host}:${endpoint.port}`);
        });

        tcp.on("data", (data) => {
          if (ws.readyState === ws.OPEN) ws.send(data);
          logTraffic(cert, endpoint, "download", data);
        });

        ws.on("message", (data) => {
          const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
          if (!tcp.destroyed) tcp.write(buf);
          logTraffic(cert, endpoint, "upload", buf);
        });

        tcp.on("error", (e) => { log(`tcp error: ${e.message}`); ws.close(); });
        tcp.on("close", () => { log("tcp closed"); ws.close(); });
        ws.on("close", (code) => { log(`ws close code=${code}`); tcp.destroy(); });
        ws.on("error", (e) => { log(`ws error: ${e.message}`); tcp.destroy(); });
      });
    } catch (e) {
      log("upgrade error:", e.message);
      socket.write("HTTP/1.1 404 Not Found\r\n\r\n");
      socket.destroy();
    }
  });

  server.listen(port, () => {
    log(`mTLS WebSocket tunnel on :${port}`);
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
