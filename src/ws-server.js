import tls from "node:tls";
import net from "node:net";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { execSync } from "node:child_process";
import { WebSocketServer } from "ultimate-ws";
import { getCACert, ensureCA } from "./ca.js";
import { getDB } from "./db.js";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const INTERNAL_WS_PORT = 19876;
const PREVIEW_MAX = 256;

export async function startWSServer(port) {
  const { caCert } = ensureCA();
  const serverTls = generateServerCert();

  const wsServer = new WebSocketServer({
    port: INTERNAL_WS_PORT,
    handleUpgrade: async (request) => {
      const fingerprint = request.headers["x-client-fingerprint"];
      const targetId = request.headers["x-target"];

      if (!fingerprint || !targetId) {
        return deny(request);
      }

      const db = getDB();
      const cert = await db.collection("certificates").findOne({ fingerprint });
      if (!cert) return deny(request);

      const endpoint = await db.collection("endpoints").findOne({ targetId });
      if (!endpoint) return deny(request);

      if (!cert.allowedEndpoints.includes(targetId)) {
        return deny(request);
      }

      return (ws) => {
        const tcp = net.createConnection(
          { host: endpoint.host, port: endpoint.port },
          () => { /* connected */ }
        );

        tcp.on("data", (data) => {
          try { ws.send(data); } catch { /* closed */ }
          logTraffic(db, cert, endpoint, "download", data);
        });

        ws.on("message", (data) => {
          const buf = Buffer.from(data);
          if (!tcp.destroyed) tcp.write(buf);
          logTraffic(db, cert, endpoint, "upload", buf);
        });

        tcp.on("close", () => ws.close());
        tcp.on("error", () => ws.close());
        ws.on("close", () => tcp.destroy());
        ws.on("error", () => tcp.destroy());

        wsServer.emit("connection", ws);
      };
    },
  });

  const tlsServer = tls.createServer(
    {
      key: serverTls.key,
      cert: serverTls.cert,
      ca: [caCert],
      requestCert: true,
      rejectUnauthorized: true,
    },
    (tlsSocket) => {
      const peerCert = tlsSocket.getPeerCertificate(true);
      if (!peerCert || !peerCert.raw) {
        tlsSocket.destroy();
        return;
      }

      const fingerprint = crypto
        .createHash("sha256")
        .update(peerCert.raw)
        .digest("hex");

      const internal = net.createConnection(
        { host: "127.0.0.1", port: INTERNAL_WS_PORT },
        () => {
          let first = true;
          tlsSocket.on("data", (data) => {
            if (first) {
              first = false;
              const str = data.toString("utf-8");
              const injected = str.replace(
                "\r\n\r\n",
                `\r\nx-client-fingerprint: ${fingerprint}\r\n\r\n`
              );
              internal.write(injected);
            } else {
              internal.write(data);
            }
          });
          internal.on("data", (data) => {
            if (!tlsSocket.destroyed) tlsSocket.write(data);
          });
        }
      );

      internal.on("close", () => tlsSocket.destroy());
      internal.on("error", () => tlsSocket.destroy());
      tlsSocket.on("close", () => internal.destroy());
      tlsSocket.on("error", () => internal.destroy());
    }
  );

  tlsServer.listen(port, () => {
    console.log(`[ws] mTLS tunnel on :${port} → internal ws :${INTERNAL_WS_PORT}`);
  });
}

function deny(request) {
  request.res.cork(() => {
    request.res.writeStatus("404 Not Found");
    request.res.end();
  });
  return false;
}

function makePreview(buf) {
  // Try UTF-8 first; if it looks like text, show it
  const str = buf.toString("utf-8", 0, Math.min(buf.length, PREVIEW_MAX));
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x08\x0E-\x1F]/.test(str.slice(0, 64))) {
    // Binary — show hex
    return buf.toString("hex", 0, Math.min(buf.length, 64)) + (buf.length > 64 ? "…" : "");
  }
  return str + (buf.length > PREVIEW_MAX ? "…" : "");
}

function generateServerCert() {
  const caDir = path.join(__dirname, "..", "data", "ca");
  const caKeyFile = path.join(caDir, "ca-key.pem");
  const caCertFile = path.join(caDir, "ca-cert.pem");
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "bastion-srv-"));

  try {
    const keyFile = path.join(tmpDir, "key.pem");
    const csrFile = path.join(tmpDir, "csr.pem");
    const certFile = path.join(tmpDir, "cert.pem");
    const serial = crypto.randomBytes(8).toString("hex");

    execSync(`openssl ecparam -genkey -name prime256v1 -noout -out "${keyFile}"`, { stdio: "pipe" });
    execSync(`openssl req -new -key "${keyFile}" -out "${csrFile}" -subj "/CN=bastion-tunnel"`, { stdio: "pipe" });
    execSync(
      `openssl x509 -req -in "${csrFile}" -CA "${caCertFile}" -CAkey "${caKeyFile}" -set_serial 0x${serial} -out "${certFile}" -days 365`,
      { stdio: "pipe" }
    );

    return {
      key: fs.readFileSync(keyFile, "utf-8"),
      cert: fs.readFileSync(certFile, "utf-8"),
    };
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function logTraffic(db, cert, endpoint, direction, data) {
  const doc = {
    userId: cert.userId,
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
  };
  // Fire and forget — don't slow down the tunnel
  db.collection("audit_logs").insertOne(doc).catch(() => {});
}
