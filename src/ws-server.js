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
        const cert = await db.collection("certificates").findOne({ fingerprint }, { projection: { _id: 1, limitInKiB: 1, limitOutKiB: 1, usedInBytes: 1, usedOutBytes: 1, tunnelUserId: 1, endpointId: 1 } });
        if (!cert) {
          res.writeHead(403, { "Content-Type": "text/plain" });
          return res.end("cert not registered\n");
        }
        const now = new Date();
        const window = cert.endpointId ? await db.collection("access_windows").findOne({
          tunnelUserId: cert.tunnelUserId, endpointId: cert.endpointId,
          active: true, from: { $lte: now }, until: { $gte: now },
        }) : null;
        const limitIn = cert.limitInKiB || 0;
        const limitOut = cert.limitOutKiB || 0;
        const usedIn = cert.usedInBytes || 0;
        const usedOut = cert.usedOutBytes || 0;
        const remainIn = limitIn > 0 ? Math.max(0, limitIn * 1024 - usedIn) : -1;
        const remainOut = limitOut > 0 ? Math.max(0, limitOut * 1024 - usedOut) : -1;
        res.writeHead(200, {
          "Content-Type": "text/plain",
          "X-Limit-In-KiB": String(limitIn),
          "X-Limit-Out-KiB": String(limitOut),
          "X-Used-In-Bytes": String(usedIn),
          "X-Used-Out-Bytes": String(usedOut),
          "X-Remain-In-Bytes": String(remainIn),
          "X-Remain-Out-Bytes": String(remainOut),
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

      // Check bandwidth limits — reject but don't delete
      const limitInBytes = (cert.limitInKiB || 0) * 1024;
      const limitOutBytes = (cert.limitOutKiB || 0) * 1024;
      if (limitInBytes > 0 && (cert.usedInBytes || 0) >= limitInBytes) {
        return reject(socket, "403 Forbidden", "upload limit exceeded");
      }
      if (limitOutBytes > 0 && (cert.usedOutBytes || 0) >= limitOutBytes) {
        return reject(socket, "403 Forbidden", "download limit exceeded");
      }

      log(`GRANTED: ${cert.name} → ${endpoint.host}:${endpoint.port}`);

      wss.handleUpgrade(req, socket, head, (ws) => {
        const tcp = net.createConnection({ host: endpoint.host, port: endpoint.port });
        tcp.setNoDelay(true);
        let tcpReady = false;
        const buf = [];
        tcp.on("connect", () => { log(`tcp connected ${endpoint.host}:${endpoint.port}`); tcpReady = true; for (const b of buf) tcp.write(b); buf.length = 0; });
        tcp.on("data", (data) => {
          if (ws.readyState === 1) ws.send(data);
          db.collection("certificates").updateOne({ _id: cert._id }, { $inc: { usedOutBytes: data.length } }).catch(() => {});
          bus.emit("cert:bandwidth", { certId: String(cert._id), usedInBytes: null, usedOutBytes: data.length, inc: true });
          logTraffic(cert, endpoint, "download", data);
        });
        ws.on("message", (data) => {
          const chunk = Buffer.isBuffer(data) ? data : Buffer.from(data);
          if (tcpReady) tcp.write(chunk); else buf.push(chunk);
          db.collection("certificates").updateOne({ _id: cert._id }, { $inc: { usedInBytes: chunk.length } }).catch(() => {});
          bus.emit("cert:bandwidth", { certId: String(cert._id), usedInBytes: chunk.length, usedOutBytes: null, inc: true });
          logTraffic(cert, endpoint, "upload", chunk);
        });
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
  const doc = {
    userId: cert.tunnelUserId, userName: cert._userName || null,
    certId: cert._id, certName: cert.name, fingerprint: cert.fingerprint,
    endpointId: endpoint._id, endpointName: endpoint.name,
    targetHost: endpoint.host, targetPort: endpoint.port,
    direction, bytes: data.length, preview: makePreview(data),
    rawHex: data.toString("hex"), ts: new Date(),
  };
  db.collection("audit_logs").insertOne(doc).then((r) => {
    bus.emit("audit:log", { ...doc, _id: r.insertedId, rawHex: undefined });
  }).catch(() => {});
}
