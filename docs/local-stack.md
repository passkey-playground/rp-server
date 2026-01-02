# Runnable Local Stack

This repo ships a single docker-compose stack for Postgres, Redis, and the RP server.

## Prereqs
- Docker Desktop (or Docker Engine + Compose v2)

## Quick start
```bash
cp .env.example .env

docker compose up --build
```

App endpoints:
- RP server: http://localhost:8090
- Swagger UI: http://localhost:8090/swagger-ui.html
- Passkey UI: http://localhost:8090/fido2/ui

## Seeds
Postgres seeds are loaded from `scripts/storage/sql/` on first boot.

## Stop
```bash
docker compose down
```

## Reset data
```bash
docker compose down -v
```
