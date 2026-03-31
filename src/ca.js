import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CA_DIR = path.join(__dirname, "..", "data", "ca");
const CA_KEY = path.join(CA_DIR, "ca-key.pem");
const CA_CERT = path.join(CA_DIR, "ca-cert.pem");

export function ensureCA() {
  fs.mkdirSync(CA_DIR, { recursive: true });
  if (!fs.existsSync(CA_KEY) || !fs.existsSync(CA_CERT)) {
    execSync(`openssl ecparam -genkey -name prime256v1 -noout -out "${CA_KEY}"`, { stdio: "pipe" });
    execSync(`openssl req -new -x509 -key "${CA_KEY}" -out "${CA_CERT}" -days 3650 -subj "/CN=Bastion Internal CA"`, { stdio: "pipe" });
    console.log("[ca] created internal CA");
  }
  return {
    caCert: fs.readFileSync(CA_CERT, "utf-8"),
    caKey: fs.readFileSync(CA_KEY, "utf-8"),
  };
}

export function getCACert() {
  return ensureCA().caCert;
}

export function getCACertPath() {
  ensureCA();
  return CA_CERT;
}

export function getCAKeyPath() {
  ensureCA();
  return CA_KEY;
}

/**
 * Signs a CSR with the internal CA. Returns { cert, fingerprint }.
 */
export function signCSR(csrPem) {
  ensureCA();
  const tmpDir = fs.mkdtempSync(path.join(CA_DIR, "tmp-"));
  try {
    const csrFile = path.join(tmpDir, "client.csr");
    const certFile = path.join(tmpDir, "client-cert.pem");
    const serial = crypto.randomBytes(8).toString("hex");

    fs.writeFileSync(csrFile, csrPem);
    execSync(
      `openssl x509 -req -in "${csrFile}" -CA "${CA_CERT}" -CAkey "${CA_KEY}" -set_serial 0x${serial} -out "${certFile}" -days 365`,
      { stdio: "pipe" }
    );

    const cert = fs.readFileSync(certFile, "utf-8");
    const der = execSync(`openssl x509 -in "${certFile}" -outform DER`, { encoding: "buffer" });
    const fingerprint = crypto.createHash("sha256").update(der).digest("hex");
    return { cert, fingerprint };
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

/**
 * Generates a server TLS cert signed by the internal CA. Returns { key, cert } PEM strings.
 */
export function generateServerCert() {
  ensureCA();
  const tmpDir = fs.mkdtempSync(path.join(CA_DIR, "tmp-"));
  try {
    const keyFile = path.join(tmpDir, "key.pem");
    const csrFile = path.join(tmpDir, "csr.pem");
    const certFile = path.join(tmpDir, "cert.pem");
    const extFile = path.join(tmpDir, "ext.cnf");
    const serial = crypto.randomBytes(8).toString("hex");

    // SAN config so the cert is valid for localhost, 127.0.0.1, and any hostname
    fs.writeFileSync(extFile, [
      "subjectAltName=DNS:localhost,DNS:bastion-tunnel,DNS:*,IP:127.0.0.1,IP:0.0.0.0",
    ].join("\n"));

    execSync(`openssl ecparam -genkey -name prime256v1 -noout -out "${keyFile}"`, { stdio: "pipe" });
    execSync(`openssl req -new -key "${keyFile}" -out "${csrFile}" -subj "/CN=bastion-tunnel"`, { stdio: "pipe" });
    execSync(
      `openssl x509 -req -in "${csrFile}" -CA "${CA_CERT}" -CAkey "${CA_KEY}" -set_serial 0x${serial} -out "${certFile}" -days 365 -extfile "${extFile}"`,
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
