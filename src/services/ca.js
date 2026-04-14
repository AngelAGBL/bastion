import { execSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";

// CA certs are expected to exist at this path (mounted as volume).
// Set CA_DIR env to override. The app will NOT auto-generate them.
const CA_DIR = process.env.CA_DIR || path.join(process.cwd(), "data", "ca");
const CA_KEY = path.join(CA_DIR, "ca.key");
const CA_CERT = path.join(CA_DIR, "ca.crt");

function generateEd25519Key() {
  const { privateKey } = crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return privateKey;
}

function fingerprint(certPem) {
  const x509 = new crypto.X509Certificate(certPem);
  return crypto.createHash("sha256").update(x509.raw).digest("hex");
}

/**
 * Loads the CA cert and key from disk. Throws if they don't exist.
 */
export function ensureCA() {
  if (!fs.existsSync(CA_KEY) || !fs.existsSync(CA_CERT)) {
    throw new Error(
      `CA certificates not found at ${CA_DIR}. ` +
      `Generate them with: openssl genpkey -algorithm Ed25519 -out ca.key && ` +
      `openssl req -new -x509 -key ca.key -out ca.crt -days 3650 -subj "/CN=Bastion Internal CA"`
    );
  }
  return {
    caCert: fs.readFileSync(CA_CERT, "utf-8"),
    caKey: fs.readFileSync(CA_KEY, "utf-8"),
  };
}

export function getCACert() { return ensureCA().caCert; }
export function getCACertPath() { ensureCA(); return CA_CERT; }

export function generateClientCert(commonName, days = 365) {
  ensureCA();
  const privateKey = generateEd25519Key();
  const wsHost = process.env.WSHOST || "localhost:3001";
  const cn = wsHost.replace(/[^a-zA-Z0-9._:\- ]/g, "_");
  const serial = crypto.randomBytes(8).toString("hex");
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "bastion-cert-"));
  try {
    const kf = path.join(tmp, "k.pem"), cf = path.join(tmp, "c.csr"), of = path.join(tmp, "o.pem");
    fs.writeFileSync(kf, privateKey, { mode: 0o600 });
    execSync(`openssl req -new -key "${kf}" -out "${cf}" -subj "/CN=${cn}"`, { stdio: "pipe" });
    execSync(`openssl x509 -req -in "${cf}" -CA "${CA_CERT}" -CAkey "${CA_KEY}" -set_serial 0x${serial} -out "${of}" -days ${days}`, { stdio: "pipe" });
    const certPem = fs.readFileSync(of, "utf-8");
    return { certPem, keyPem: privateKey, fingerprint: fingerprint(certPem) };
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
}

export function generateServerCert() {
  ensureCA();
  const serverKey = path.join(CA_DIR, "server.key");
  const serverCert = path.join(CA_DIR, "server.crt");
  if (!fs.existsSync(serverKey) || !fs.existsSync(serverCert)) {
    throw new Error(
      `Server TLS certificates not found at ${CA_DIR}/server.key and server.crt. ` +
      `Place your server key and cert there (e.g. from Let's Encrypt or self-signed).`
    );
  }
  return { key: fs.readFileSync(serverKey, "utf-8"), cert: fs.readFileSync(serverCert, "utf-8") };
}

export function generateP12(certPem, keyPem, password) {
  ensureCA();
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "bastion-p12-"));
  try {
    const cf = path.join(tmp, "cert.pem"), kf = path.join(tmp, "key.pem"), pf = path.join(tmp, "bundle.p12");
    fs.writeFileSync(cf, certPem);
    fs.writeFileSync(kf, keyPem, { mode: 0o600 });
    execSync(`openssl pkcs12 -export -out "${pf}" -inkey "${kf}" -in "${cf}" -certfile "${CA_CERT}" -passout pass:${password.replace(/'/g, "\\'")}`, { stdio: "pipe" });
    return fs.readFileSync(pf);
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
}
