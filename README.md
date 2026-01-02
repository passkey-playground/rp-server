# RP Server (FIDO/Passkeys)

- Relying Party (RP) server implementation for FIDO2/WebAuthn passkeys using spring-boot and webauthn4j.

## Docs (start here)
- docs/README.md

## Swagger UI + OpenAPI
- Swagger UI: http://localhost:8090/swagger-ui.html
- OpenAPI JSON: http://localhost:8090/v3/api-docs
- Source spec: docs/openapi.yaml

## Requirements
- Java 17
- Postgres
- Redis

## Storage setup
Provisioning scripts live in `scripts/storage`. A storage-specific README lives
there as well; refer to it during storage setup for the exact steps.

## Configuration
This project is a Spring Boot app. Configure database and cache settings in
`src/main/resources/application.properties` or via environment variables.

## Container and Fly.io
A `Dockerfile` is included to run the app as a container. For Fly.io deployment,
use the included `fly.toml` alongside the Dockerfile.

## Runnable local stack (Postgres + Redis + rp-server)
```bash
cp .env.example .env
docker compose up --build
```

## Local dev
```bash
make dev
```

## Test + lint
```bash
make test
make lint
```

### Fly.io deployment
1. Install the Fly.io CLI: `curl -L https://fly.io/install.sh | sh`
2. Authenticate: `fly auth login`
3. Initialize (if needed): `fly launch` (choose the existing `fly.toml` when prompted)
4. Set required secrets (database, cache, and app config):
   - Example: `fly secrets set SPRING_DATASOURCE_URL=... SPRING_DATASOURCE_USERNAME=... SPRING_DATASOURCE_PASSWORD=...`
5. Deploy: `fly deploy`
6. Check status and logs:
   - `fly status`
   - `fly logs`
