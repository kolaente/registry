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
  tls:
    enabled: false  # Use Traefik or nginx for TLS termination
```

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

### Authentication

```yaml
auth:
  realm: "Registry"
  service: "Docker Registry"
  issuer: "registry-auth-server"
  private_key: "/data/keys/registry.key"
  public_key: "/data/keys/registry.pub"
```

RSA keys are auto-generated on first run if they don't exist.

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
│    │     - RSA key management          │   │
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

- Go 1.23+
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
go test ./...
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
│   └── registry/         # Registry handler
│       └── handler.go
├── config.example.yaml   # Example configuration
├── Dockerfile           # Multi-stage build
├── docker-compose.yml   # Basic deployment
└── docker-compose.traefik.yml  # Traefik deployment
```

## Security Considerations

- **Passwords**: Always use bcrypt-hashed passwords with cost ≥10
- **Keys**: Keep RSA private keys secure; use file permissions 0600
- **TLS**: Use HTTPS in production (Traefik, nginx, or enable built-in TLS)
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
