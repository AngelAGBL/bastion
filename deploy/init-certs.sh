#!/bin/sh
# Generate self-signed server cert for nginx if not exists
CERT_DIR="./certs"
mkdir -p "$CERT_DIR"

if [ ! -f "$CERT_DIR/server.crt" ]; then
  echo "Generating self-signed server certificate..."
  openssl req -x509 -nodes -days 365 \
    -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.crt" \
    -subj "/CN=bastion-tunnel" \
    -addext "subjectAltName=DNS:localhost,DNS:*,IP:127.0.0.1"
  echo "Done: $CERT_DIR/server.crt"
else
  echo "Server cert already exists, skipping."
fi
