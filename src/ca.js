import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CA_DIR = path.join(__dirname, "..", "data", "ca");
const CA_KEY = path.join(CA_DIR, "ca-key.pem");
const CA_CERT = path.join(CA_DIR, "ca-cert.pem");

/** Generate EC P-256 key pair as PEM using node:crypto (no openssl). */
function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "P-256",
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { publicKey, privateKey };
}

/** Compute SHA-256 fingerprint of a PEM certificate. */
function fingerprint(certPem) {
  const x509 = new crypto.X509Certificate(certPem);
  return crypto.createHash("sha256").update(x509.raw).digest("hex");
}

/** Ensure the internal CA exists. Only uses openssl for self-signed CA cert (one-time). */
export function ensureCA() {
  fs.mkdirSync(CA_DIR, { recursive: true });
  if (!fs.existsSync(CA_KEY) || !fs.existsSync(CA_CERT)) {
    const { privateKey } = generateKeyPair();
    fs.writeFileSync(CA_KEY, privateKey, { mode: 0o600 });
    // Self-signed CA cert — openssl needed only here (no node API for X.509 creation)
    execSync(
      `openssl req -new -x509 -key "${CA_KEY}" -out "${CA_CERT}" -days 3650 -subj "/CN=Bastion Internal CA"`,
      { stdio: "pipe" }
    );
    console.log("[ca] created internal CA");
  }
  return {
    caCert: fs.readFileSync(CA_CERT, "utf-8"),
    caKey: fs.readFileSync(CA_KEY, "utf-8"),
  };
}

export function getCACert() { return ensureCA().caCert; }
export function getCACertPath() { ensureCA(); return CA_CERT; }

/**
 * Generate a client cert signed by the CA.
 * Key pair generated with node:crypto, signing with openssl (minimal).
 * Returns { certPem, keyPem, fingerprint }
 */
export function generateClientCert(commonName, days = 365) {
  ensureCA();
  const { privateKey } = generateKeyPair();
  const cn = commonName.replace(/[^a-zA-Z0-9._\- ]/g, "_");
  const serial = crypto.randomBytes(8).toString("hex");
  const tmp = fs.mkdtempSync(path.join(CA_DIR, "tmp-"));
  try {
    const kf = path.join(tmp, "k.pem");
    const cf = path.join(tmp, "c.csr");
    const of = path.join(tmp, "o.pem");
    fs.writeFileSync(kf, privateKey, { mode: 0o600 });
    // CSR + sign — two openssl calls, unavoidable for X.509 signing
    execSync(`openssl req -new -key "${kf}" -out "${cf}" -subj "/CN=${cn}"`, { stdio: "pipe" });
    execSync(`openssl x509 -req -in "${cf}" -CA "${CA_CERT}" -CAkey "${CA_KEY}" -set_serial 0x${serial} -out "${of}" -days ${days}`, { stdio: "pipe" });
    const certPem = fs.readFileSync(of, "utf-8");
    return { certPem, keyPem: privateKey, fingerprint: fingerprint(certPem) };
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

/** Generate server TLS cert with SANs. */
export function generateServerCert() {
  ensureCA();
  const { privateKey } = generateKeyPair();
  const serial = crypto.randomBytes(8).toString("hex");
  const tmp = fs.mkdtempSync(path.join(CA_DIR, "tmp-"));
  try {
    const kf = path.join(tmp, "k.pem");
    const cf = path.join(tmp, "c.csr");
    const ef = path.join(tmp, "e.cnf");
    const of = path.join(tmp, "o.pem");
    fs.writeFileSync(kf, privateKey, { mode: 0o600 });
    fs.writeFileSync(ef, "subjectAltName=DNS:localhost,DNS:bastion-tunnel,DNS:*,IP:127.0.0.1,IP:0.0.0.0");
    execSync(`openssl req -new -key "${kf}" -out "${cf}" -subj "/CN=bastion-tunnel"`, { stdio: "pipe" });
    execSync(`openssl x509 -req -in "${cf}" -CA "${CA_CERT}" -CAkey "${CA_KEY}" -set_serial 0x${serial} -out "${of}" -days 365 -extfile "${ef}"`, { stdio: "pipe" });
    return { key: privateKey, cert: fs.readFileSync(of, "utf-8") };
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

/**
 * Generate PKCS#12 (.p12) bundle containing client cert + key + CA cert.
 * Returns Buffer with the .p12 data.
 */
export function generateP12(certPem, keyPem, password) {
  const tmp = fs.mkdtempSync(path.join(CA_DIR, "tmp-"));
  try {
    const cf = path.join(tmp, "cert.pem");
    const kf = path.join(tmp, "key.pem");
    const pf = path.join(tmp, "bundle.p12");
    fs.writeFileSync(cf, certPem);
    fs.writeFileSync(kf, keyPem, { mode: 0o600 });
    // Single openssl call for p12 export
    execSync(
      `openssl pkcs12 -export -out "${pf}" -inkey "${kf}" -in "${cf}" -certfile "${CA_CERT}" -passout pass:${password.replace(/'/g, "\\'")}`,
      { stdio: "pipe" }
    );
    return fs.readFileSync(pf);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}
