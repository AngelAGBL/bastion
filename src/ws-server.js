import crypto from "node:crypto";
import net from "node:net";
import https from "node:https";
import { WebSocketServer } from "ws";
import { ObjectId } from "mongodb";
import { ensureCA, generateServerCert, getCACert } from "./services/ca.js";
import { getDB } from "./services/db.js";
import bus from "./services/events.js";

const PREVIEW_MAX = 256;

function log(...args) {
  const msg = args.map(a => typeof a === "object" ? JSON.stringify(a) : String(a)).join(" ");
  console.log(`[ws ${new Date().toISOString()}] ${msg}`);
}

function reject(socket, code, reason) {
  log(`REJECT: ${reason}`);
  try { socket.write(`HTTP/1.1 ${code}\r\nX-Error: ${reason}\r\nConnection: close\r\n\r\n`); } catch {}
  socket.destroy();
}

export async function startWSServer(port) {
  ensureCA();
  const serverTls = generateServerCert();
  const caCertPem = getCACert();

  const server = https.createServer({
    key: serverTls.key,
    cert: serverTls.cert,
    ca: [caCertPem],
    requestCert: true,
    rejectUnauthorized: true,
  });

  server.on("tlsClientError", (err, tlsSocket) => {
    log(`TLS REJECT: ${err.message}`);
    tlsSocket.destroy();
  });

  server.on("request", async (req, res) => {
    try {
      if (req.url === "/verify") {
        const peerCert = req.socket.getPeerCertificate(true);
        if (!peerCert || !peerCert.raw || peerCert.raw.length === 0) {
          res.writeHead(403, { "Content-Type": "text/plain" });
          return res.end("no cert\n");
        }
        const fingerprint = crypto.createHash("sha256").update(peerCert.raw).digest("hex");
        const db = getDB();
        const cert = await db.collection("certificates").findOne({ fingerprint }, { projection: { _id: 1, uses: 1, tunnelUserId: 1, endpointId: 1 } });
        if (!cert) {
          res.writeHead(403, { "Content-Type": "text/plain" });
          return res.end("cert not registered\n");
        }
        const now = new Date();
        const window = cert.endpointId ? await db.collection("access_windows").findOne({
          tunnelUserId: cert.tunnelUserId, endpointId: cert.endpointId,
          active: true, from: { $lte: now }, until: { $gte: now },
        }) : null;
        const uses = cert.uses > 0 ? cert.uses : -1;
        res.writeHead(200, {
          "Content-Type": "text/plain",
          "X-Remaining-Uses": String(uses),
          "X-Active": window ? "true" : "false",
          "Connection": "close",
        });
        return res.end("ok\n");
      }
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("bastion-ws alive\n");
    } catch (e) {
      log("request error:", e.message);
      try { res.writeHead(500); res.end("error\n"); } catch {}
    }
  });

  const wss = new WebSocketServer({
    noServer: true,
    skipUTF8Validation: true,
    handleProtocols: (protocols) => {
      if (protocols.has("v1")) return "v1";
      return false;
    },
  });

  server.on("upgrade", async (req, socket, head) => {
    log(`upgrade: path=${req.url}`);
    const peerCert = req.socket.getPeerCertificate(true);
    if (!peerCert || !peerCert.raw || peerCert.raw.length === 0) {
      return reject(socket, "403 Forbidden", "no client cert");
    }
    const fingerprint = crypto.createHash("sha256").update(peerCert.raw).digest("hex");
    log(`fp=${fingerprint.slice(0, 16)}…`);

    try {
      const db = getDB();
      const cert = await db.collection("certificates").findOne({ fingerprint });
      if (!cert) return reject(socket, "403 Forbidden", "cert not in DB");

      let userName = null;
      try { const tu = await db.collection("tunnel_users").findOne({ _id: new ObjectId(cert.tunnelUserId) }); userName = tu?.name || null; } catch {}
      cert._userName = userName;

      const endpoint = await db.collection("endpoints").findOne({ _id: cert.endpointId });
      if (!endpoint) return reject(socket, "403 Forbidden", "endpoint not found");

      const now = new Date();
      const window = await db.collection("access_windows").findOne({
        tunnelUserId: cert.tunnelUserId, endpointId: endpoint._id,
        active: true, from: { $lte: now }, until: { $gte: now },
      });
      if (!window) return reject(socket, "403 Forbidden", "no active access window");

      if (cert.uses > 0) {
        const remaining = cert.uses - 1;
        if (remaining <= 0) {
          await db.collection("certificates").deleteOne({ _id: cert._id });
          log(`cert ${cert.name}: last use — deleted`);
          bus.emit("cert:uses", { certId: String(cert._id), uses: 0 });
        } else {
          await db.collection("certificates").updateOne({ _id: cert._id }, { $inc: { uses: -1 } });
          log(`cert ${cert.name}: uses left ${remaining}`);
          bus.emit("cert:uses", { certId: String(cert._id), uses: remaining });
        }
      }

      log(`GRANTED: ${cert.name} → ${endpoint.host}:${endpoint.port}`);

      wss.handleUpgrade(req, socket, head, (ws) => {
        const tcp = net.createConnection({ host: endpoint.host, port: endpoint.port });
        tcp.setNoDelay(true);
        let tcpReady = false;
        const buf = [];
        tcp.on("connect", () => { log(`tcp connected ${endpoint.host}:${endpoint.port}`); tcpReady = true; for (const b of buf) tcp.write(b); buf.length = 0; });
        tcp.on("data", (data) => { if (ws.readyState === 1) ws.send(data); logTraffic(cert, endpoint, "download", data); });
        ws.on("message", (data) => { const chunk = Buffer.isBuffer(data) ? data : Buffer.from(data); if (tcpReady) tcp.write(chunk); else buf.push(chunk); logTraffic(cert, endpoint, "upload", chunk); });
        tcp.on("error", (e) => { log(`tcp err: ${e.message}`); ws.close(); });
        tcp.on("close", () => ws.close());
        ws.on("close", (code) => { log(`ws closed code=${code}`); tcp.destroy(); });
        ws.on("error", (e) => { log(`ws err: ${e.message}`); tcp.destroy(); });
      });
    } catch (e) {
      log("error:", e.message);
      reject(socket, "500 Internal Server Error", e.message);
    }
  });

  server.listen(port, () => log(`mTLS WS tunnel on :${port}`));
}

function makePreview(buf) {
  return buf.toString("utf-8", 0, Math.min(buf.length, PREVIEW_MAX)).replace(/[\x00-\x08\x0E-\x1F]/g, "�");
}

function logTraffic(cert, endpoint, direction, data) {
  const db = getDB();
  db.collection("audit_logs").insertOne({
    userId: cert.tunnelUserId, userName: cert._userName || null,
    certId: cert._id, certName: cert.name, fingerprint: cert.fingerprint,
    endpointId: endpoint._id, endpointName: endpoint.name,
    targetHost: endpoint.host, targetPort: endpoint.port,
    direction, bytes: data.length, preview: makePreview(data),
    rawHex: data.toString("hex"), ts: new Date(),
  }).catch(() => {});
}
