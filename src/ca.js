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

export function getCACert() { return ensureCA().caCert; }
export function getCACertPath() { ensureCA(); return CA_CERT; }
export function getCAKeyPath() { ensureCA(); return CA_KEY; }

/**
 * Generates a client key pair + signed cert.
 * Returns { certPem, keyPem, fingerprint }
 */
export function generateClientCert(commonName, days = 365) {
  ensureCA();
  const tmpDir = fs.mkdtempSync(path.join(CA_DIR, "tmp-"));
  try {
    const keyFile = path.join(tmpDir, "client-key.pem");
    const csrFile = path.join(tmpDir, "client.csr");
    const certFile = path.join(tmpDir, "client-cert.pem");
    const serial = crypto.randomBytes(8).toString("hex");
    const cn = commonName.replace(/[^a-zA-Z0-9._\- ]/g, "_");

    execSync(`openssl ecparam -genkey -name prime256v1 -noout -out "${keyFile}"`, { stdio: "pipe" });
    execSync(`openssl req -new -key "${keyFile}" -out "${csrFile}" -subj "/CN=${cn}"`, { stdio: "pipe" });
    execSync(`openssl x509 -req -in "${csrFile}" -CA "${CA_CERT}" -CAkey "${CA_KEY}" -set_serial 0x${serial} -out "${certFile}" -days ${days}`, { stdio: "pipe" });

    const keyPem = fs.readFileSync(keyFile, "utf-8");
    const certPem = fs.readFileSync(certFile, "utf-8");
    const der = execSync(`openssl x509 -in "${certFile}" -outform DER`, { encoding: "buffer" });
    const fingerprint = crypto.createHash("sha256").update(der).digest("hex");

    return { certPem, keyPem, fingerprint };
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

/** Generates a server TLS cert signed by the internal CA. */
export function generateServerCert() {
  ensureCA();
  const tmpDir = fs.mkdtempSync(path.join(CA_DIR, "tmp-"));
  try {
    const keyFile = path.join(tmpDir, "key.pem");
    const csrFile = path.join(tmpDir, "csr.pem");
    const certFile = path.join(tmpDir, "cert.pem");
    const extFile = path.join(tmpDir, "ext.cnf");
    const serial = crypto.randomBytes(8).toString("hex");

    fs.writeFileSync(extFile, "subjectAltName=DNS:localhost,DNS:bastion-tunnel,DNS:*,IP:127.0.0.1,IP:0.0.0.0");
    execSync(`openssl ecparam -genkey -name prime256v1 -noout -out "${keyFile}"`, { stdio: "pipe" });
    execSync(`openssl req -new -key "${keyFile}" -out "${csrFile}" -subj "/CN=bastion-tunnel"`, { stdio: "pipe" });
    execSync(`openssl x509 -req -in "${csrFile}" -CA "${CA_CERT}" -CAkey "${CA_KEY}" -set_serial 0x${serial} -out "${certFile}" -days 365 -extfile "${extFile}"`, { stdio: "pipe" });

    return { key: fs.readFileSync(keyFile, "utf-8"), cert: fs.readFileSync(certFile, "utf-8") };
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

/** PowerShell script — writes cert+key to temp files, runs wstunnel. */
export function generatePowershellScript({ keyPem, certPem, wsHost }) {
  return `# Bastion Tunnel Client - PowerShell
$ErrorActionPreference = "Stop"

$certPem = @"
${certPem.trim()}
"@

$keyPem = @"
${keyPem.trim()}
"@

$wsHost = "${wsHost}"

$port = Read-Host -Prompt "Puerto local a bindear"

$tempDir = Join-Path $env:TEMP "bastion-$(Get-Random)"
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

try {
    $certFile = Join-Path $tempDir "client.crt"
    $keyFile = Join-Path $tempDir "client.key"

    [IO.File]::WriteAllText($certFile, $certPem)
    [IO.File]::WriteAllText($keyFile, $keyPem)

    # Buscar wstunnel
    $wstunnel = Get-Command wstunnel -ErrorAction SilentlyContinue
    if ($wstunnel) {
        $wsBin = $wstunnel.Source
    } else {
        $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
        $local = Join-Path $scriptDir "wstunnel.exe"
        if (Test-Path $local) { $wsBin = $local }
        else { Write-Error "wstunnel no encontrado en PATH ni en el directorio del script."; exit 1 }
    }

    Write-Host "Conectando al tunel en puerto $port..." -ForegroundColor Green
    & $wsBin client --tls-certificate $certFile --tls-private-key $keyFile -L "tcp/$port\`:.:0" "wss://$wsHost"

} finally {
    Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
}
`;
}

/** POSIX shell script — writes cert+key to temp files, runs wstunnel. */
export function generateShellScript({ keyPem, certPem, wsHost }) {
  return `#!/bin/sh
set -e

CERT_PEM=$(cat <<'CERTEOF'
${certPem.trim()}
CERTEOF
)

KEY_PEM=$(cat <<'KEYEOF'
${keyPem.trim()}
KEYEOF
)

WS_HOST="${wsHost}"

printf "Puerto local a bindear: "
read PORT

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

printf '%s' "$CERT_PEM" > "$TMPDIR/client.crt"
printf '%s' "$KEY_PEM" > "$TMPDIR/client.key"
chmod 600 "$TMPDIR/client.key"

# Buscar wstunnel
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
if command -v wstunnel >/dev/null 2>&1; then
    WSTUNNEL=wstunnel
elif [ -x "$SCRIPT_DIR/wstunnel" ]; then
    WSTUNNEL="$SCRIPT_DIR/wstunnel"
else
    echo "Error: wstunnel no encontrado en PATH ni en el directorio del script." >&2
    exit 1
fi

echo "Conectando al tunel en puerto $PORT..."

"$WSTUNNEL" client \\
    --tls-certificate "$TMPDIR/client.crt" \\
    --tls-private-key "$TMPDIR/client.key" \\
    -L "tcp://$PORT:.:0" \\
    "wss://$WS_HOST"
`;
}
