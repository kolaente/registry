# Docker Registry with Integrated Authentication

A self-contained, single-binary Docker registry with built-in JWT authentication and ACL support. No separate authentication service needed.

## Features

- **Single Binary**: Everything runs in one process - no microservices complexity
- **Integrated Authentication**: Built-in JWT token service, no separate auth server required
- **ACL Support**: Fine-grained access control with glob pattern matching
- **Simple Configuration**: Single YAML file for users, permissions, and settings
- **Production Ready**: Built on the official `distribution/distribution` library
- **Docker Native**: Fully compatible with Docker and containerd clients
- **Lightweight**: Final Docker image built from scratch (~50-100MB)

## Quick Start

### 1. Create Configuration

```bash
cp config.example.yaml config.yaml
```

Edit `config.yaml` to customize users and permissions. Generate password hashes with:

```bash
htpasswd -nbBC 10 username password
```

### 2. Deploy with Docker Compose

```bash
docker-compose up -d
```

The registry will be available at `http://localhost:5000`.

### 3. Test the Registry

```bash
# Login
docker login localhost:5000
# Username: admin
# Password: password

# Tag and push an image
docker tag alpine:latest localhost:5000/myorg/alpine:latest
docker push localhost:5000/myorg/alpine:latest

# Pull the image
docker pull localhost:5000/myorg/alpine:latest
```

## Configuration

### Server Settings

```yaml
server:
  addr: ":5000"
```

**Note:** This registry only supports HTTP. For production deployments with HTTPS/TLS, use a reverse proxy like Traefik, nginx, or Caddy. See the [Docker Compose with Traefik](#option-2-docker-compose-with-traefik-https) section for an example.

### Users

Users are defined with bcrypt-hashed passwords:

```yaml
users:
  admin:
    password: "$2y$10$..."
  developer:
    password: "$2y$10$..."
```

### Access Control Lists (ACL)

ACL rules support glob patterns for repository names:

```yaml
acl:
  # Admin has full access
  - account: "admin"
    name: "*"
    actions: ["*"]

  # Developer can push/pull to backend-* repos
  - account: "developer"
    name: "myorg/backend-*"
    actions: ["pull", "push"]

  # Developer can only pull from frontend
  - account: "developer"
    name: "myorg/frontend"
    actions: ["pull"]
```

**Supported Actions:**
- `pull` - Download images
- `push` - Upload images
- `delete` - Delete images
- `*` - All actions

**Pattern Matching:**
- `*` - Matches any repository
- `myorg/*` - Matches all repos under myorg
- `backend-*` - Matches backend-api, backend-service, etc.
- `exact-name` - Exact match only

### Storage

```yaml
storage:
  filesystem:
    rootdirectory: "/data/registry"
```

### Garbage Collection

The registry includes automatic garbage collection to clean up unreferenced blobs and optionally remove untagged manifests.

```yaml
garbage_collector:
  enabled: true          # Enable automatic garbage collection
  interval: "24h"        # How often to run GC (e.g., "24h", "1h30m")
  remove_untagged: true  # Remove manifests not referenced by any tag
```

**How it works:**
- When `remove_untagged: true`, manifests that aren't referenced by any tag are deleted
- All blob layers that are no longer referenced by any manifest are cleaned up
- GC runs automatically at the configured interval when `enabled: true`

**Manual Garbage Collection:**

You can also run garbage collection manually via the CLI:

```bash
# Run garbage collection
./registry gc --config config.yaml --delete-untagged

# Dry run (show what would be deleted without deleting)
./registry gc --config config.yaml --delete-untagged --dry-run
```

### Authentication

The registry supports two JWT signing methods: **RSA** (asymmetric) and **HMAC** (symmetric).

#### RSA Signing (Default)

Uses public/private key pairs for token signing. Best for distributed systems where tokens are validated by multiple services.

```yaml
auth:
  realm: "Registry"
  service: "Docker Registry"
  issuer: "registry-auth-server"
  signing_method: "rsa"  # Default, can be omitted
  private_key: "/data/keys/registry.key"
  public_key: "/data/keys/registry.pub"
```

RSA keys are auto-generated on first run if they don't exist.

#### HMAC Signing

Uses a shared secret for token signing. Simpler and faster than RSA, ideal for single-server deployments.

```yaml
auth:
  realm: "Registry"
  service: "Docker Registry"
  issuer: "registry-auth-server"
  signing_method: "hmac"
  hmac_secret: "your-secret-key-here"
```

Generate a secure HMAC secret:

```bash
openssl rand -base64 32
```

#### When to Use Each Method

**Use RSA when:**
- You have a distributed system with multiple services validating tokens
- You need to share the public key for external token validation
- You want asymmetric cryptography for enhanced security

**Use HMAC when:**
- Running a single-server deployment (auth and registry in one process)
- You want simpler configuration with no key files
- You prioritize performance (HMAC is computationally faster)
- The secret can be kept secure within the application

## Deployment Options

### Option 1: Docker Compose (HTTP)

Basic deployment for local development or internal networks:

```bash
docker-compose up -d
```

### Option 2: Docker Compose with Traefik (HTTPS)

For production with automatic HTTPS certificates:

1. Update `docker-compose.traefik.yml` with your domain
2. Ensure Traefik is running with Let's Encrypt configured
3. Deploy:

```bash
docker-compose -f docker-compose.traefik.yml up -d
```

### Option 3: Build and Run Binary

```bash
# Build
go build -o registry ./cmd/registry

# Run
./registry --config config.yaml
```

### Option 4: Build Docker Image

```bash
docker build -t registry:latest .
docker run -p 5000:5000 \
  -v $(pwd)/config.yaml:/etc/registry/config.yaml:ro \
  -v registry-data:/data/registry \
  registry:latest
```

## Usage Examples

### Login

```bash
docker login registry.example.com
```

### Push Image

```bash
docker tag myapp:latest registry.example.com/myorg/myapp:v1.0
docker push registry.example.com/myorg/myapp:v1.0
```

### Pull Image

```bash
docker pull registry.example.com/myorg/myapp:v1.0
```

### Test with curl

```bash
# Get token
TOKEN=$(curl -u admin:password \
  "http://localhost:5000/v2/token?service=Docker%20Registry&scope=repository:myorg/test:pull,push" \
  | jq -r .token)

# List repositories (requires authentication)
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:5000/v2/_catalog
```

## Architecture

```
┌─────────────────────────────────────────────┐
│         Single Binary Application           │
│                                             │
│  ┌──────────────────────────────────────┐  │
│  │   HTTP Router (Go stdlib)            │  │
│  └──────────────────────────────────────┘  │
│           │              │                  │
│           │              │                  │
│    ┌──────▼─────┐  ┌────▼──────────────┐   │
│    │ /v2/token  │  │ /v2/* (Registry)  │   │
│    │            │  │                   │   │
│    │ Auth       │  │ Auth Middleware   │   │
│    │ Handler    │  │        │          │   │
│    └──────┬─────┘  └────────┼──────────┘   │
│           │                 │              │
│           │                 │              │
│    ┌──────▼─────────────────▼──────────┐   │
│    │     JWT Token Service             │   │
│    │     - Generate tokens             │   │
│    │     - Validate signatures         │   │
│    │     - RSA or HMAC signing         │   │
│    └──────┬────────────────────────────┘   │
│           │                                │
│    ┌──────▼──────────────────┐            │
│    │  ACL Matcher            │            │
│    │  - Glob patterns        │            │
│    │  - Permission checks    │            │
│    └──────┬──────────────────┘            │
│           │                                │
│    ┌──────▼──────────────────┐            │
│    │  distribution/registry  │            │
│    │  - Blob storage         │            │
│    │  - Manifest handling    │            │
│    │  - V2 API               │            │
│    └─────────────────────────┘            │
└─────────────────────────────────────────────┘
```

## Development

### Prerequisites

- Go 1.25+
- Docker (for testing)

### Build

```bash
go build -o registry ./cmd/registry
```

### Run Locally

```bash
./registry --config config.yaml
```

### Run Tests

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./pkg/...

# Run with race detection
go test -race ./pkg/...

# Generate coverage report
make test-coverage
```

### Project Structure

```
.
├── cmd/
│   └── registry/          # Main application entry point
│       └── main.go
├── pkg/
│   ├── acl/              # ACL matching engine
│   │   └── matcher.go
│   ├── auth/             # Authentication & JWT
│   │   ├── handler.go    # /v2/token endpoint
│   │   └── token.go      # JWT service
│   ├── config/           # Configuration
│   │   └── config.go
│   ├── gc/               # Garbage collection
│   │   └── gc.go         # GC service and CLI
│   └── registry/         # Registry handler
│       └── handler.go
├── config.example.yaml   # Example configuration
├── Dockerfile           # Multi-stage build
├── docker-compose.yml   # Basic deployment
└── docker-compose.traefik.yml  # Traefik deployment
```

## Security Considerations

- **Passwords**: Always use bcrypt-hashed passwords with cost ≥10
- **Keys & Secrets**:
  - RSA: Keep private keys secure; use file permissions 0600
  - HMAC: Use strong secrets (≥32 bytes); never commit to version control
  - Rotate secrets regularly
- **TLS**: Always use a reverse proxy (Traefik, nginx, Caddy) for TLS termination in production. Built-in TLS is not supported. See `docker-compose.traefik.yml` for an example
- **Network**: Run on internal network or behind reverse proxy
- **Updates**: Pin distribution library version and review security updates

## Troubleshooting

### "unauthorized: authentication required"

- Verify credentials are correct
- Check user exists in config.yaml
- Ensure password hash is valid bcrypt format

### "access denied"

- Review ACL rules in config.yaml
- Check if repository name matches ACL pattern
- Verify requested action is allowed for the user

### "failed to create registry handler"

- Check storage directory exists and is writable
- Verify config.yaml syntax is valid
- Review logs for specific error messages

### Docker client timeout

- Ensure registry is running: `docker ps`
- Check health endpoint: `curl http://localhost:5000/health`
- Verify port 5000 is accessible

## License

This project is provided as-is for self-hosting Docker registries.

## Contributing

Contributions welcome! Please test changes thoroughly and follow conventional commit messages.

## Acknowledgments

- Built on [distribution/distribution](https://github.com/distribution/distribution)
- Inspired by [cesanta/docker_auth](https://github.com/cesanta/docker_auth)
- JWT handling via [golang-jwt/jwt](https://github.com/golang-jwt/jwt)
