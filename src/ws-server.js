import crypto from "node:crypto";
import net from "node:net";
import tls from "node:tls";
import dgram from "node:dgram";
import uWS from "uWebSockets.js";
import { ObjectId } from "mongodb";
import { ensureCA, generateServerCert, getCACert } from "./services/ca.js";
import { getDB } from "./services/db.js";
import bus from "./services/events.js";

const PROXY_MODE = process.env.TLS_MODE === "proxy";
const INTERNAL_PORT = 19876;
const certLocks = new Map();
const certSockets = new Map();

function log(...args) {
  const msg = args.map(a => typeof a === "object" ? JSON.stringify(a) : String(a)).join(" ");
  console.log(`[ws ${new Date().toISOString()}] ${msg}`);
}

function releaseCertLock(fp) {
  const lock = certLocks.get(fp);
  if (lock) { lock.count--; if (lock.count <= 0) certLocks.delete(fp); }
}

function headerStr(req, key) {
  return req.getHeader(key);
}

function allHeaders(req) {
  const h = {};
  req.forEach((k, v) => { h[k] = v; });
  return h;
}

export async function startWSServer(port) {
  const uwsApp = uWS.App();

  // --- HTTP: / handler (verify + health) ---
  uwsApp.get("/*", async (res, req) => {
    let aborted = false;
    res.onAborted(() => { aborted = true; });

    const fp = headerStr(req, "x-fingerprint") || headerStr(req, "x-ssl-client-fingerprint");
    if (!fp) {
      if (!aborted) res.cork(() => { res.writeStatus("200 OK").writeHeader("Content-Type", "text/plain").end("bastion-ws alive\n"); });
      return;
    }

    try {
      const db = getDB();
      const cert = await db.collection("certificates").findOne({ fingerprint: fp },
        { projection: { _id: 1, limitInKiB: 1, limitOutKiB: 1, usedInBytes: 1, usedOutBytes: 1, tunnelUserId: 1, endpointId: 1 } });
      if (!cert) {
        if (!aborted) res.cork(() => res.writeStatus("403 Forbidden").end("cert not registered\n"));
        return;
      }
      const now = new Date();
      const window = cert.endpointId ? await db.collection("access_windows").findOne({
        tunnelUserId: cert.tunnelUserId, endpointId: cert.endpointId,
        active: true, from: { $lte: now }, until: { $gte: now },
      }) : null;
      const epSecs = window ? Math.max(0, Math.floor((new Date(window.until).getTime() - now.getTime()) / 1000)) : 0;

      if (!aborted) res.cork(() => {
        res.writeStatus("200 OK")
          .writeHeader("Content-Type", "text/plain")
          .writeHeader("X-Limit-In-KiB", String(cert.limitInKiB || 0))
          .writeHeader("X-Limit-Out-KiB", String(cert.limitOutKiB || 0))
          .writeHeader("X-Used-In-Bytes", String(cert.usedInBytes || 0))
          .writeHeader("X-Used-Out-Bytes", String(cert.usedOutBytes || 0))
          .writeHeader("X-Endpoint-Seconds", String(epSecs))
          .writeHeader("Connection", "close")
          .end("ok\n");
      });
    } catch (e) {
      log("request error:", e.message);
      if (!aborted) res.cork(() => res.writeStatus("500").end("error\n"));
    }
  });

  // --- WebSocket ---
  uwsApp.ws("/*", {
    maxPayloadLength: 16 * 1024 * 1024,
    idleTimeout: 0,
    sendPingsAutomatically: false,

    upgrade: async (res, req, context) => {
      let aborted = false;
      res.onAborted(() => { aborted = true; });

      const fp = headerStr(req, "x-fingerprint") || headerStr(req, "x-ssl-client-fingerprint");
      const secKey = headerStr(req, "sec-websocket-key");
      const secProto = headerStr(req, "sec-websocket-protocol");
      const secExt = headerStr(req, "sec-websocket-extensions");
      const remoteIP = headerStr(req, "x-forwarded-for")?.split(",")[0]?.trim() || Buffer.from(res.getRemoteAddressAsText()).toString();

      log(`upgrade: fp=${fp?.slice(0, 16) || "-"}`);

      if (!fp) {
        if (!aborted) res.cork(() => res.writeStatus("403 Forbidden").end());
        return;
      }

      try {
        const db = getDB();
        const cert = await db.collection("certificates").findOne({ fingerprint: fp });
        if (!cert) { if (!aborted) res.cork(() => res.writeStatus("403 Forbidden").end()); return; }

        let userName = null;
        try { const tu = await db.collection("tunnel_users").findOne({ _id: new ObjectId(cert.tunnelUserId) }); userName = tu?.name || null; } catch {}
        cert._userName = userName;

        const endpoint = await db.collection("endpoints").findOne({ _id: cert.endpointId });
        if (!endpoint) { if (!aborted) res.cork(() => res.writeStatus("403 Forbidden").end()); return; }

        const now = new Date();
        const window = await db.collection("access_windows").findOne({
          tunnelUserId: cert.tunnelUserId, endpointId: endpoint._id,
          active: true, from: { $lte: now }, until: { $gte: now },
        });
        if (!window) { if (!aborted) res.cork(() => res.writeStatus("403 Forbidden").end()); return; }

        const limitInBytes = (cert.limitInKiB || 0) * 1024;
        const limitOutBytes = (cert.limitOutKiB || 0) * 1024;
        if (limitInBytes > 0 && (cert.usedInBytes || 0) >= limitInBytes) { if (!aborted) res.cork(() => res.writeStatus("403 Forbidden").end()); return; }
        if (limitOutBytes > 0 && (cert.usedOutBytes || 0) >= limitOutBytes) { if (!aborted) res.cork(() => res.writeStatus("403 Forbidden").end()); return; }

        const lock = certLocks.get(fp);
        if (lock && lock.ip !== remoteIP) { if (!aborted) res.cork(() => res.writeStatus("403 Forbidden").end()); return; }

        log(`GRANTED: ${cert.name} → ${endpoint.protocol || "tcp"}://${endpoint.host}:${endpoint.port}`);
        if (lock) lock.count++; else certLocks.set(fp, { ip: remoteIP, count: 1 });

        if (!aborted) {
          res.cork(() => {
            res.upgrade(
              { cert, endpoint, fingerprint: fp, limitIn: limitInBytes, limitOut: limitOutBytes },
              secKey, "v1", secExt, context
            );
          });
        }
      } catch (e) {
        log("upgrade error:", e.message);
        if (!aborted) res.cork(() => res.writeStatus("500").end());
      }
    },

    open: (ws) => {
      const { cert, endpoint, fingerprint, limitIn, limitOut } = ws.getUserData();
      log(`open: ${cert.name} → ${endpoint.host}:${endpoint.port}`);

      if (!certSockets.has(fingerprint)) certSockets.set(fingerprint, new Set());
      certSockets.get(fingerprint).add(ws);

      const db = getDB();
      let totalIn = cert.usedInBytes || 0;
      let totalOut = cert.usedOutBytes || 0;

      function checkLimits() {
        if ((limitIn > 0 && totalIn >= limitIn) || (limitOut > 0 && totalOut >= limitOut)) {
          log(`cert ${cert.name}: bandwidth limit — closing ALL`);
          const socks = certSockets.get(fingerprint);
          if (socks) for (const s of socks) { try { s.close(); } catch {} }
        }
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

      const proto = endpoint.protocol || "tcp";

      if (proto === "udp") {
        const udp = dgram.createSocket("udp4");
        udp.on("message", (msg) => { try { ws.send(msg, true); } catch {} trackDown(msg); });
        udp.on("error", (e) => { log(`udp err: ${e.message}`); try { ws.close(); } catch {} });
        ws._udp = udp;
        ws._trackUp = trackUp;
      } else {
        const tcp = net.createConnection({ host: endpoint.host, port: endpoint.port });
        tcp.setNoDelay(true);
        let ready = false;
        const buf = [];
        tcp.on("connect", () => { log(`tcp connected ${endpoint.host}:${endpoint.port}`); ready = true; for (const b of buf) tcp.write(b); buf.length = 0; });
        tcp.on("data", (d) => { try { ws.send(d, true); } catch {} trackDown(d); });
        tcp.on("error", (e) => { log(`tcp err: ${e.message}`); try { ws.close(); } catch {} });
        tcp.on("close", () => { try { ws.close(); } catch {} });
        ws._tcp = tcp;
        ws._tcpReady = () => ready;
        ws._tcpBuf = buf;
        ws._trackUp = trackUp;
      }
    },

    message: (ws, message) => {
      const chunk = Buffer.from(message);
      if (ws._udp) {
        const { endpoint } = ws.getUserData();
        ws._udp.send(chunk, endpoint.port, endpoint.host);
      } else if (ws._tcp) {
        if (ws._tcpReady()) ws._tcp.write(chunk);
        else ws._tcpBuf.push(chunk);
      }
      if (ws._trackUp) ws._trackUp(chunk);
    },

    close: (ws, code) => {
      const { cert, fingerprint } = ws.getUserData();
      log(`ws close: ${cert.name} code=${code}`);
      releaseCertLock(fingerprint);
      const socks = certSockets.get(fingerprint);
      if (socks) { socks.delete(ws); if (socks.size === 0) certSockets.delete(fingerprint); }
      if (ws._tcp) ws._tcp.destroy();
      if (ws._udp) { try { ws._udp.close(); } catch {} }
    },
  });

  // --- Start ---
  if (PROXY_MODE) {
    // Proxy mode: uWS listens directly, TLS handled by reverse proxy
    uwsApp.listen(port, (sock) => {
      if (sock) log(`uWS tunnel on :${port} (proxy mode)`);
      else log(`FAILED to listen on :${port}`);
    });
  } else {
    // Direct mTLS: tls.createServer → proxy to internal uWS
    uwsApp.listen(INTERNAL_PORT, (sock) => {
      if (sock) log(`internal uWS on :${INTERNAL_PORT}`);
      else log(`FAILED internal listen :${INTERNAL_PORT}`);
    });

    ensureCA();
    const serverTls = generateServerCert();
    const caCertPem = getCACert();

    const tlsServer = tls.createServer({
      key: serverTls.key, cert: serverTls.cert, ca: [caCertPem],
      requestCert: true, rejectUnauthorized: false,
    }, (tlsSocket) => {
      tlsSocket.setNoDelay(true);
      const peerCert = tlsSocket.getPeerCertificate(true);
      if (!peerCert || !peerCert.raw || peerCert.raw.length === 0) { tlsSocket.end(); return; }

      const x509 = new crypto.X509Certificate(peerCert.raw);
      if (!x509.verify(crypto.createPublicKey(caCertPem))) { tlsSocket.end(); return; }

      const fingerprint = crypto.createHash("sha256").update(peerCert.raw).digest("hex");

      const internal = net.createConnection({ host: "127.0.0.1", port: INTERNAL_PORT });
      internal.setNoDelay(true);
      let first = true;

      tlsSocket.on("data", (data) => {
        if (internal.destroyed) return;
        if (first) {
          first = false;
          const str = data.toString("utf-8");
          const idx = str.indexOf("\r\n\r\n");
          if (idx !== -1) {
            internal.write(str.slice(0, idx) + `\r\nx-fingerprint: ${fingerprint}` + str.slice(idx));
          } else {
            internal.write(data);
          }
        } else {
          internal.write(data);
        }
      });

      internal.on("data", (d) => { if (!tlsSocket.destroyed) tlsSocket.write(d); });
      internal.on("end", () => tlsSocket.end());
      internal.on("error", () => tlsSocket.end());
      internal.on("close", () => { if (!tlsSocket.destroyed) tlsSocket.destroy(); });
      tlsSocket.on("end", () => internal.end());
      tlsSocket.on("error", () => internal.destroy());
      tlsSocket.on("close", () => { if (!internal.destroyed) internal.destroy(); });
    });

    tlsServer.on("tlsClientError", (err) => log(`TLS REJECT: ${err.message}`));
    tlsServer.listen(port, () => log(`mTLS proxy on :${port} → uWS :${INTERNAL_PORT}`));
  }
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
