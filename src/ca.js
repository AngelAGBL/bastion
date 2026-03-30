import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CA_DIR = path.join(__dirname, "..", "data", "ca");
const CA_KEY = path.join(CA_DIR, "ca-key.pem");
const CA_CERT = path.join(CA_DIR, "ca-cert.pem");

/**
 * Ensures the internal CA exists. Creates it on first run.
 * Returns { caCert, caKey } as PEM strings.
 */
export function ensureCA() {
  fs.mkdirSync(CA_DIR, { recursive: true });

  if (!fs.existsSync(CA_KEY) || !fs.existsSync(CA_CERT)) {
    // Generate CA private key
    execSync(`openssl ecparam -genkey -name prime256v1 -noout -out "${CA_KEY}"`, { stdio: "pipe" });
    // Generate self-signed CA certificate (10 years)
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

/**
 * Issues a client certificate signed by the internal CA.
 * Returns { clientCert, clientKey, fingerprint } as PEM strings.
 */
export function issueClientCert(commonName) {
  const { caKey, caCert } = ensureCA();
  const tmpDir = fs.mkdtempSync(path.join(CA_DIR, "tmp-"));

  try {
    const keyFile = path.join(tmpDir, "client-key.pem");
    const csrFile = path.join(tmpDir, "client.csr");
    const certFile = path.join(tmpDir, "client-cert.pem");
    const serial = crypto.randomBytes(8).toString("hex");

    // Generate client key
    execSync(`openssl ecparam -genkey -name prime256v1 -noout -out "${keyFile}"`, { stdio: "pipe" });

    // Generate CSR
    execSync(
      `openssl req -new -key "${keyFile}" -out "${csrFile}" -subj "/CN=${commonName.replace(/[^a-zA-Z0-9._-]/g, "_")}"`,
      { stdio: "pipe" }
    );

    // Sign with CA (1 year)
    execSync(
      `openssl x509 -req -in "${csrFile}" -CA "${CA_CERT}" -CAkey "${CA_KEY}" -set_serial 0x${serial} -out "${certFile}" -days 365`,
      { stdio: "pipe" }
    );

    const clientKey = fs.readFileSync(keyFile, "utf-8");
    const clientCert = fs.readFileSync(certFile, "utf-8");

    // Fingerprint = SHA-256 of the DER-encoded certificate
    const derHex = execSync(`openssl x509 -in "${certFile}" -outform DER`, { encoding: "buffer" });
    const fingerprint = crypto.createHash("sha256").update(derHex).digest("hex");

    return { clientCert, clientKey, fingerprint };
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

/**
 * Returns the CA certificate PEM (for configuring TLS server).
 */
export function getCACert() {
  return ensureCA().caCert;
}

/**
 * Computes SHA-256 fingerprint from a PEM-encoded certificate string.
 * Returns hex string or throws if the PEM is invalid.
 */
export function fingerprintFromPEM(pem) {
  const tmpDir = fs.mkdtempSync(path.join(CA_DIR, "tmp-"));
  try {
    const certFile = path.join(tmpDir, "cert.pem");
    fs.writeFileSync(certFile, pem);
    const der = execSync(`openssl x509 -in "${certFile}" -outform DER`, { encoding: "buffer" });
    return crypto.createHash("sha256").update(der).digest("hex");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}
