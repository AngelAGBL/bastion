# Bastion — Deploy con Nginx + mTLS proxy

## Inicio rápido

```bash
cd deploy

# 1. Generar cert de servidor para nginx (solo la primera vez)
./init-certs.sh

# 2. Levantar
docker compose up -d --build

# 3. Acceder
# Dashboard: http://localhost (admin:123456)
# Tunnel WS: wss://localhost:443 (mTLS via nginx)
```

## Arquitectura

```
Cliente ──mTLS──▶ nginx:443
                    │ ssl_verify_client
                    │ X-SSL-Client-Verify
                    │ X-SSL-Client-Fingerprint
                    ▼
                  app:3001 (uWS, TLS_MODE=proxy)
                    │ TCP/UDP tunnel
                    ▼
                  destino

Browser ──HTTP──▶ nginx:80 → app:3000 (dashboard)
```

## Variables de entorno (app)

| Variable | Descripción | Default |
|---|---|---|
| `TLS_MODE` | `proxy` (nginx maneja TLS) o `direct` (app maneja mTLS) | `direct` |
| `WSHOST` | CN del cert de cliente (host:port que el cliente usa) | `localhost:3001` |
| `JWT_SECRET` | Secret para tokens JWT del dashboard | — |
| `MONGO_URI` | URI de MongoDB | — |

## Producción

1. Reemplaza `server.crt`/`server.key` con certs reales (Let's Encrypt, etc.)
2. Cambia `WSHOST` al dominio real (ej: `tunnel.midominio.com:443`)
3. Cambia `JWT_SECRET` a un valor aleatorio largo
4. Configura `server_name` en nginx.conf
