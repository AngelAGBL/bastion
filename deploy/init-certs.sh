#!/bin/sh
# Generate CA and server certs for development.
# In production, replace server certs with Let's Encrypt ones.

set -e

CA_DIR="./certs"
mkdir -p "$CA_DIR"

# --- CA certs (mTLS client verification) ---
if [ ! -f "$CA_DIR/ca.key" ]; then
  echo "Generating CA (Ed25519)..."
  openssl genpkey -algorithm Ed25519 -out "$CA_DIR/ca.key"
  openssl req -new -x509 -key "$CA_DIR/ca.key" -out "$CA_DIR/ca.crt" \
    -days 3650 -subj "/CN=Bastion Internal CA"
  chmod 600 "$CA_DIR/ca.key"
  echo "Done: $CA_DIR/ca.crt"
else
  echo "CA certs exist, skipping."
fi

# --- Server TLS certs (mTLS tunnel endpoint) ---
# In production: copy your Let's Encrypt fullchain.pem → server.crt, server.pem → server.key
if [ ! -f "$CA_DIR/server.key" ]; then
  echo "Generating self-signed server cert (replace with Let's Encrypt in production)..."
  openssl req -x509 -nodes -days 365 \
    -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$CA_DIR/server.key" \
    -out "$CA_DIR/server.crt" \
    -subj "/CN=bastion-tunnel" \
    -addext "subjectAltName=DNS:localhost,DNS:*,IP:127.0.0.1"
  chmod 600 "$CA_DIR/server.key"
  echo "Done: $CA_DIR/server.crt"
else
  echo "Server certs exist, skipping."
fi