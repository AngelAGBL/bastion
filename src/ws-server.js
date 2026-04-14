import crypto from "node:crypto";
import net from "node:net";
import http from "node:http";
import dgram from "node:dgram";
import https from "node:https";
import { WebSocketServer } from "ws";
import { ObjectId } from "mongodb";
import { ensureCA, generateServerCert, getCACert } from "./services/ca.js";
import { getDB } from "./services/db.js";
import bus from "./services/events.js";

const PROXY_MODE = process.env.TLS_MODE === "proxy";
const certLocks = new Map();
const certSockets = new Map();

function log(...args) {
  const msg = args.map(a => typeof a === "object" ? JSON.stringify(a) : String(a)).join(" ");
  console.log(`[ws ${new Date().toISOString()}] ${msg}`);
}

function reject(socket, code, reason) {
  log(`REJECT: ${reason}`);
  try { socket.write(`HTTP/1.1 ${code}\r\nX-Error: ${reason}\r\nConnection: close\r\n\r\n`); } catch {}
  socket.destroy();
}

function releaseCertLock(fp) {
  const lock = certLocks.get(fp);
  if (lock) { lock.count--; if (lock.count <= 0) certLocks.delete(fp); }
}

/**
 * Extract fingerprint from request.
 * Direct mTLS: from TLS peer certificate.
 * Proxy mode: from X-SSL-Client-Fingerprint header (proxy must set X-SSL-Client-Verify=SUCCESS).
 */
function extractFingerprint(req) {
  if (PROXY_MODE) {
    const verify = req.headers["x-ssl-client-verify"];
    if (verify !== "SUCCESS") return null;
    const fp = req.headers["x-ssl-client-fingerprint"];
    return fp ? fp.replace(/:/g, "").toLowerCase() : null;
  }
  const peerCert = req.socket.getPeerCertificate?.(true);
  if (!peerCert || !peerCert.raw || peerCert.raw.length === 0) return null;
  return crypto.createHash("sha256").update(peerCert.raw).digest("hex");
}

function getRemoteIP(req) {
  if (PROXY_MODE) return req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket.remoteAddress;
  return req.socket.remoteAddress;
}

export async function startWSServer(port) {
  let server;

  if (PROXY_MODE) {
    log("mode: PROXY (TLS terminated by reverse proxy)");
    server = http.createServer();
  } else {
    log("mode: DIRECT mTLS");
    ensureCA();
    const serverTls = generateServerCert();
    const caCertPem = getCACert();
    server = https.createServer({
      key: serverTls.key, cert: serverTls.cert, ca: [caCertPem],
      requestCert: true, rejectUnauthorized: true,
    });
    server.on("tlsClientError", (err) => log(`TLS REJECT: ${err.message}`));
  }

  // --- HTTP handler: / serves both verify (with cert) and health check ---
  server.on("request", async (req, res) => {
    try {
      const fp = extractFingerprint(req);
      if (!fp) {
        res.writeHead(200, { "Content-Type": "text/plain" });
        return res.end("bastion-ws alive\n");
      }

      const db = getDB();
      const cert = await db.collection("certificates").findOne({ fingerprint: fp },
        { projection: { _id: 1, limitInKiB: 1, limitOutKiB: 1, usedInBytes: 1, usedOutBytes: 1, tunnelUserId: 1, endpointId: 1 } });
      if (!cert) {
        res.writeHead(403, { "Content-Type": "text/plain" });
        return res.end("cert not registered\n");
      }

      const now = new Date();
      const window = cert.endpointId ? await db.collection("access_windows").findOne({
        tunnelUserId: cert.tunnelUserId, endpointId: cert.endpointId,
        active: true, from: { $lte: now }, until: { $gte: now },
      }) : null;

      const endpointSecs = window ? Math.max(0, Math.floor((new Date(window.until).getTime() - now.getTime()) / 1000)) : 0;

      res.writeHead(200, {
        "Content-Type": "text/plain",
        "X-Limit-In-KiB": String(cert.limitInKiB || 0),
        "X-Limit-Out-KiB": String(cert.limitOutKiB || 0),
        "X-Used-In-Bytes": String(cert.usedInBytes || 0),
        "X-Used-Out-Bytes": String(cert.usedOutBytes || 0),
        "X-Endpoint-Seconds": String(endpointSecs),
        "Connection": "close",
      });
      return res.end("ok\n");
    } catch (e) {
      log("request error:", e.message);
      try { res.writeHead(500); res.end("error\n"); } catch {}
    }
  });

  // --- WebSocket ---
  const wss = new WebSocketServer({
    noServer: true, skipUTF8Validation: true,
    handleProtocols: (protocols) => protocols.has("v1") ? "v1" : false,
  });

  server.on("upgrade", async (req, socket, head) => {
    log(`upgrade: path=${req.url}`);
    const fingerprint = extractFingerprint(req);
    if (!fingerprint) return reject(socket, "403 Forbidden", "no client cert");
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

      const limitInBytes = (cert.limitInKiB || 0) * 1024;
      const limitOutBytes = (cert.limitOutKiB || 0) * 1024;
      if (limitInBytes > 0 && (cert.usedInBytes || 0) >= limitInBytes) return reject(socket, "403 Forbidden", "upload limit exceeded");
      if (limitOutBytes > 0 && (cert.usedOutBytes || 0) >= limitOutBytes) return reject(socket, "403 Forbidden", "download limit exceeded");

      const remoteIP = getRemoteIP(req);
      const lock = certLocks.get(fingerprint);
      if (lock && lock.ip !== remoteIP) return reject(socket, "403 Forbidden", "cert in use from another IP");

      log(`GRANTED: ${cert.name} → ${endpoint.protocol || "tcp"}://${endpoint.host}:${endpoint.port}`);
      if (lock) lock.count++; else certLocks.set(fingerprint, { ip: remoteIP, count: 1 });

      wss.handleUpgrade(req, socket, head, (ws) => {
        if (!certSockets.has(fingerprint)) certSockets.set(fingerprint, new Set());
        certSockets.get(fingerprint).add(ws);

        const proto = endpoint.protocol || "tcp";
        const limitIn = limitInBytes;
        const limitOut = limitOutBytes;
        let totalIn = cert.usedInBytes || 0;
        let totalOut = cert.usedOutBytes || 0;

        function checkLimits() {
          if ((limitIn > 0 && totalIn >= limitIn) || (limitOut > 0 && totalOut >= limitOut)) {
            log(`cert ${cert.name}: bandwidth limit — closing ALL`);
            const socks = certSockets.get(fingerprint);
            if (socks) for (const s of socks) { try { s.close(); } catch {} }
            return true;
          }
          return false;
        }

        function cleanup() {
          releaseCertLock(fingerprint);
          const socks = certSockets.get(fingerprint);
          if (socks) { socks.delete(ws); if (socks.size === 0) certSockets.delete(fingerprint); }
        }

        function trackUp(chunk) {
          totalIn += chunk.length;
          db.collection("certificates").updateOne({ _id: cert._id }, { $inc: { usedInBytes: chunk.length } }).catch(() => {});
          bus.emit("cert:bandwidth", { certId: String(cert._id), usedInBytes: chunk.length, inc: true });
          logTraffic(cert, endpoint, "upload", chunk);
          checkLimits();
        }

        function trackDown(data) {
          totalOut += data.length;
          db.collection("certificates").updateOne({ _id: cert._id }, { $inc: { usedOutBytes: data.length } }).catch(() => {});
          bus.emit("cert:bandwidth", { certId: String(cert._id), usedOutBytes: data.length, inc: true });
          logTraffic(cert, endpoint, "download", data);
          checkLimits();
        }

        if (proto === "udp") {
          const udp = dgram.createSocket("udp4");
          udp.on("message", (msg) => { if (ws.readyState === 1) ws.send(msg); trackDown(msg); });
          udp.on("error", (e) => { log(`udp err: ${e.message}`); ws.close(); });
          ws.on("message", (data) => { const c = Buffer.isBuffer(data) ? data : Buffer.from(data); udp.send(c, endpoint.port, endpoint.host); trackUp(c); });
          ws.on("close", () => { cleanup(); try { udp.close(); } catch {} });
          ws.on("error", () => { cleanup(); try { udp.close(); } catch {} });
        } else {
          const tcp = net.createConnection({ host: endpoint.host, port: endpoint.port });
          tcp.setNoDelay(true);
          let ready = false;
          const buf = [];
          tcp.on("connect", () => { log(`tcp connected ${endpoint.host}:${endpoint.port}`); ready = true; for (const b of buf) tcp.write(b); buf.length = 0; });
          tcp.on("data", (d) => { if (ws.readyState === 1) ws.send(d); trackDown(d); });
          ws.on("message", (d) => { const c = Buffer.isBuffer(d) ? d : Buffer.from(d); if (ready) tcp.write(c); else buf.push(c); trackUp(c); });
          tcp.on("error", (e) => { log(`tcp err: ${e.message}`); ws.close(); });
          tcp.on("close", () => ws.close());
          ws.on("close", (code) => { log(`ws closed code=${code}`); cleanup(); tcp.destroy(); });
          ws.on("error", (e) => { log(`ws err: ${e.message}`); cleanup(); tcp.destroy(); });
        }
      });
    } catch (e) {
      log("error:", e.message);
      reject(socket, "500 Internal Server Error", e.message);
    }
  });

  server.listen(port, () => log(`WS tunnel on :${port} (${PROXY_MODE ? "proxy" : "direct mTLS"})`));
}

function logTraffic(cert, endpoint, direction, data) {
  const db = getDB();
  const doc = {
    userId: cert.tunnelUserId, userName: cert._userName || null,
    certId: cert._id, certName: cert.name, fingerprint: cert.fingerprint,
    endpointId: endpoint._id, endpointName: endpoint.name,
    targetHost: endpoint.host, targetPort: endpoint.port,
    direction, bytes: data.length, rawHex: data.toString("hex"), ts: new Date(),
  };
  db.collection("audit_logs").insertOne(doc).then((r) => {
    bus.emit("audit:log", { ...doc, _id: r.insertedId });
  }).catch(() => {});
}
