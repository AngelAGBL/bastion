import crypto from "node:crypto";
import net from "node:net";
import https from "node:https";
import { WebSocketServer } from "ws";
import { ObjectId } from "mongodb";
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

  const server = https.createServer({
    key: serverTls.key,
    cert: serverTls.cert,
    ca: [caCertPem],
    requestCert: true,
    rejectUnauthorized: false,
  });

  server.on("request", (_req, res) => {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("bastion-ws alive\n");
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

    // mTLS: extract client cert
    const tlsSocket = req.socket;
    const peerCert = tlsSocket.getPeerCertificate(true);
    const hasCert = peerCert && peerCert.raw && peerCert.raw.length > 0;

    if (!hasCert) {
      log("REJECT: no client cert");
      socket.write("HTTP/1.1 404 Not Found\r\n\r\n");
      socket.destroy();
      return;
    }

    try {
      const x509 = new crypto.X509Certificate(peerCert.raw);
      if (!x509.verify(crypto.createPublicKey(caCertPem))) {
        log("REJECT: cert not signed by CA");
        socket.write("HTTP/1.1 404 Not Found\r\n\r\n");
        socket.destroy();
        return;
      }
    } catch {
      socket.write("HTTP/1.1 404 Not Found\r\n\r\n");
      socket.destroy();
      return;
    }

    const fingerprint = crypto.createHash("sha256").update(peerCert.raw).digest("hex");
    log(`fp=${fingerprint.slice(0, 16)}…`);

    try {
      const db = getDB();

      // Find cert → get its linked endpoint
      const cert = await db.collection("certificates").findOne({ fingerprint });
      if (!cert) { log("REJECT: cert not in DB"); socket.write("HTTP/1.1 404 Not Found\r\n\r\n"); socket.destroy(); return; }

      // Resolve tunnel user name
      let userName = null;
      try { const tu = await db.collection("tunnel_users").findOne({ _id: new ObjectId(cert.tunnelUserId) }); userName = tu?.name || null; } catch {}
      cert._userName = userName;

      const endpoint = await db.collection("endpoints").findOne({ _id: cert.endpointId });
      if (!endpoint) { log("REJECT: endpoint not found"); socket.write("HTTP/1.1 404 Not Found\r\n\r\n"); socket.destroy(); return; }

      // Check access window
      const now = new Date();
      const window = await db.collection("access_windows").findOne({
        tunnelUserId: cert.tunnelUserId,
        endpointId: endpoint._id,
        active: true,
        from: { $lte: now },
        until: { $gte: now },
      });
      if (!window) { log("REJECT: no window"); socket.write("HTTP/1.1 404 Not Found\r\n\r\n"); socket.destroy(); return; }

      log(`GRANTED: ${cert.name} → ${endpoint.host}:${endpoint.port}`);

      // Decrement uses if limited (uses > 0). If it hits 0, delete the cert.
      if (cert.uses > 0) {
        const remaining = cert.uses - 1;
        if (remaining <= 0) {
          await db.collection("certificates").deleteOne({ _id: cert._id });
          log(`cert ${cert.name}: last use consumed — deleted`);
        } else {
          await db.collection("certificates").updateOne({ _id: cert._id }, { $inc: { uses: -1 } });
          log(`cert ${cert.name}: uses left ${remaining}`);
        }
      }

      wss.handleUpgrade(req, socket, head, (ws) => {
        if (ws._receiver) ws._receiver._isServer = false;

        const tcp = net.createConnection({ host: endpoint.host, port: endpoint.port });
        tcp.setNoDelay(true);
        let tcpReady = false;
        const buf = [];

        tcp.on("connect", () => {
          log(`tcp connected ${endpoint.host}:${endpoint.port}`);
          tcpReady = true;
          for (const b of buf) tcp.write(b);
          buf.length = 0;
        });

        tcp.on("data", (data) => {
          if (ws.readyState === 1) ws.send(data);
          logTraffic(cert, endpoint, "download", data);
        });

        ws.on("message", (data) => {
          const chunk = Buffer.isBuffer(data) ? data : Buffer.from(data);
          if (tcpReady) tcp.write(chunk);
          else buf.push(chunk);
          logTraffic(cert, endpoint, "upload", chunk);
        });

        tcp.on("error", (e) => { log(`tcp err: ${e.message}`); ws.close(); });
        tcp.on("close", () => ws.close());
        ws.on("close", (code) => { log(`ws closed code=${code}`); tcp.destroy(); });
        ws.on("error", (e) => { log(`ws err: ${e.message}`); tcp.destroy(); });
      });
    } catch (e) {
      log("error:", e.message);
      socket.write("HTTP/1.1 404 Not Found\r\n\r\n");
      socket.destroy();
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
    userId: cert.tunnelUserId,
    userName: cert._userName || null,
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
    rawHex: data.toString("hex"),
    ts: new Date(),
  }).catch(() => {});
}
