# Demo PostgreSQL + Redis Docker Setup

- Scripts to set up a containerized environment with Postgres and Redis using Docker Compose.
- Additional config files are included for setting up Postgres and Redis on Fly.io.

## Prerequisites

- Docker (version 20+)
- Docker Compose (v2+)
- Fly CLI (optional, for Fly.io deploys)

## Quick Start

### 1. Configure Environment Variables

- Postgres and Redis settings (eg: username/password, port numbers, etc) 
can be adjusted via environment variables.
- `env.sample` provides default values, copy it to `.env` as is or adjust values as needed:

```bash
cp .env.sample .env
```

### 2. Create the containers and start services

```bash
docker compose -f docker/docker-compose.yml up -d
```

This will:
- Build and start a PostgreSQL 15 container with initialization scripts under `sql/`
- Start a Redis 7 Alpine container
- Create persistent volumes for both services
- Set up a shared network

### 3. Verify Services are Running

```bash
docker compose -f docker/docker-compose.yml ps
```

### 4. Connect to PostgreSQL

**From your host machine:**
- Adjust the username, database name, and password as per your `.env` settings.
```bash
psql -h localhost -U postgres -d demo_db -W
```

**From inside the container:**
```bash
docker compose -f docker/docker-compose.yml exec postgres psql -U postgres -d demo_db
```

### 5. Connect to Redis

**From your host machine:**
- - Adjust the port number as per your `.env` settings.
```bash
redis-cli -h localhost -p 6379
```

**From inside the container:**
```bash
docker compose -f docker/docker-compose.yml exec redis redis-cli
```

## Project Structure

```
.
├── docker/                     # Docker Compose configuration
│   └── docker-compose.yml
├── flyio/                      # Fly.io app configs
│   ├── fly.postgres.toml
│   └── fly.redis.toml
├── sql/                        # SQL initialization scripts
│   ├── 01-PG-DDL.sql
│   └── 02-PG-DML.sql
├── .env                        # Local environment variables
├── .env.example                # Environment variables template
└── README.md
```

## Configuration

### Environment Variables

Available variables:
- `POSTGRES_USER`: PostgreSQL username (default: postgres)
- `POSTGRES_PASSWORD`: PostgreSQL password (default: password)
- `POSTGRES_DB`: Initial database name (default: demo_db)
- `POSTGRES_PORT`: External port mapping (default: 5432, Docker only)
- `REDIS_PORT`: External port mapping (default: 6379, Docker only)

### PostgreSQL Initialization Scripts

Docker Compose mounts `sql/` into `/docker-entrypoint-initdb.d`, so SQL files run on first container startup (in alphabetical order):
- `01-PG-DDL.sql`
- `02-PG-DML.sql`

To add more initialization scripts, create files like `03-custom.sql` in the `sql/` directory.

## Fly.io Setup

Postgres and Redis must be deployed as separate Fly apps (one image per app).

### 1. Create Apps

```bash
fly launch --config flyio/fly.postgres.toml
fly launch --config flyio/fly.redis.toml
```

### 2. Import Postgres Secrets

```bash
fly secrets import --app <your-postgres-app> < .env
```

### 3. Deploy

```bash
fly deploy --config flyio/fly.postgres.toml --app <your-postgres-app>
fly deploy --config flyio/fly.redis.toml --app <your-redis-app>
```

### 4. Delete Fly.io Resources

```bash
fly apps destroy <your-postgres-app>
fly apps destroy <your-redis-app>
```

To also remove volumes:

```bash
fly volumes list --app <your-postgres-app>
fly volumes destroy <volume-id> --app <your-postgres-app>
```
### NOTE: To keep things simple, Fly.io setup scripts doesn't include boostrapping sql scripts execution. Manual execution is needed after postgres container is created.

## Common Commands

### View Logs

```bash
# All services
docker compose -f docker/docker-compose.yml logs -f

# PostgreSQL only
docker compose -f docker/docker-compose.yml logs -f postgres

# Redis only
docker compose -f docker/docker-compose.yml logs -f redis
```

### Stop Services

```bash
docker compose -f docker/docker-compose.yml stop
```

### Remove Containers and Volumes

```bash
# Remove containers only
docker compose -f docker/docker-compose.yml down

# Remove containers and volumes (WARNING: deletes data)
docker compose -f docker/docker-compose.yml down -v
```

### Access Database

```bash
# PostgreSQL
docker compose -f docker/docker-compose.yml exec postgres psql -U postgres -d demo_db

# Redis
docker compose -f docker/docker-compose.yml exec redis redis-cli
```

## Troubleshooting

### PostgreSQL won't start

```bash
# Check logs
docker compose -f docker/docker-compose.yml logs postgres

# Ensure port 5432 is not in use
lsof -i :5432

# Rebuild the image
docker compose -f docker/docker-compose.yml up -d --build
```

### Redis connection refused

```bash
# Check if Redis is running
docker compose -f docker/docker-compose.yml ps redis

# Check Redis logs
docker compose -f docker/docker-compose.yml logs redis

# Test Redis connection inside container
docker compose -f docker/docker-compose.yml exec redis redis-cli ping
```

### Volumes not persisting

Ensure volumes are properly mounted:
```bash
docker volume ls
docker volume inspect demo-pg_postgres_data
```

## Connecting from Your Application

### PostgreSQL Connection String

```
postgresql://postgres:<password>@localhost:5432/demo_db
```

### Redis Connection

```
redis://localhost:6379
```
