## Development Plan: Self-Contained Single-Binary Docker Registry in Go

Building a single self-contained binary is a viable and simpler approach than managing separate services. Here's a practical development plan:[1][2][3][4][5]

### Phase 1: Architecture & Foundation (1-2 days)

**1.1 Core Design**
- Embed the `distribution/distribution` library as the registry backend[5][1]
- Build integrated token auth directly into the binary (no separate auth server)[2][5]
- Use a YAML config file for users and ACLs[6][7]
- Single `main.go` that initializes both registry and auth handlers

**1.2 Configuration Structure**
```yaml
# config.yaml
server:
  addr: ":5000"
  tls:
    enabled: false  # Let Traefik handle TLS

users:
  admin:
    password: "$2y$05$HASH"
  developer:
    password: "$2y$05$HASH"

acl:
  - account: "admin"
    name: "*"
    actions: ["*"]
  
  - account: "developer"
    name: "myorg/backend-*"
    actions: ["pull", "push"]
  
  - account: "developer"
    name: "myorg/frontend"
    actions: ["pull"]

storage:
  filesystem:
    rootdirectory: "/data/registry"
```

**Dependencies to add:**[5]
- `github.com/distribution/distribution/v3` — core registry
- `github.com/urfave/cli/v2` — CLI flag parsing
- `gopkg.in/yaml.v3` — config parsing
- `golang.org/x/crypto/bcrypt` — password hashing

### Phase 2: Token Auth Handler (2-3 days)

**2.1 JWT Token Service**
- Implement `/v2/token` endpoint to issue JWT tokens
- Token claims include user, account, repository scope, and actions (pull/push)[8][9]
- Sign tokens with a self-generated RSA keypair (embed in binary or load from file)

**2.2 ACL Matching Engine**
- Parse glob patterns in ACL (e.g., `backend-*`, `myorg/*`)
- Match incoming requests against ACL rules
- Return allowed actions for authenticated user + repository combination

**2.3 Integration with Distribution**
The registry will validate tokens against your JWT issuer; ensure your auth endpoint returns tokens with scope claims the registry recognizes:[10][8]
```
scope=repository:myorg/backend-service:pull,push
```

### Phase 3: Distribution Registry Embedding (3-4 days)

**3.1 HTTP Handler Setup**
- Import `github.com/distribution/distribution/v3` libraries[5]
- Create registry handler that wraps distribution's HTTP routes
- Mount registry at `/v2/*` path

**3.2 Custom Middleware**
- Intercept requests at `/v2/auth` to validate tokens
- Inject user context into distribution handlers
- Example structure:[5]
```go
package main

import (
  "github.com/distribution/distribution/v3/registry/handlers"
)

func setupRegistry() *mux.Router {
  // Initialize distribution registry
  // Add auth middleware
  // Return router
}
```

**3.3 Storage Backend Configuration**
- Use filesystem storage driver (simplest for self-hosted)[5]
- Can be extended to S3, Azure, GCS later
- Store in mounted volume: `/data/registry`

### Phase 4: Binary Build & Deployment (1-2 days)

**4.1 Single Binary Compilation**
- Compile with all config embedded or loaded from mounted file
- Use `go build -o registry-server main.go`
- Produces single `registry-server` binary (~50-100MB)

**4.2 Dockerfile**
```dockerfile
FROM golang:1.22 as builder
WORKDIR /build
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o registry-server .

FROM scratch
COPY --from=builder /build/registry-server /
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ENTRYPOINT ["/registry-server"]
EXPOSE 5000
```

**4.3 Docker Compose**
```yaml
services:
  registry:
    build: .
    ports:
      - "5000:5000"
    volumes:
      - ./config.yaml:/etc/registry/config.yaml:ro
      - registry-data:/data/registry
    environment:
      CONFIG_PATH: /etc/registry/config.yaml
volumes:
  registry-data:
```

Or with Traefik labels for automatic TLS termination:[11]
```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.registry.rule=Host(`registry.example.com`)"
  - "traefik.http.services.registry.loadbalancer.server.port=5000"
```

### Phase 5: Testing & Refinement (2-3 days)

**5.1 Unit Tests**
- Test ACL matching logic (glob patterns, edge cases)
- Test token generation and validation
- Test password hashing

**5.2 Integration Tests**
- `docker login` with valid/invalid credentials
- `docker push` with different user permissions
- `docker pull` with read-only access
- Test glob pattern permissions (e.g., `backend-*` allows `backend-api` but not `frontend`)

**5.3 Load Testing**
- Multiple concurrent pushes/pulls
- Large image handling

### Effort Estimate
- **Total: ~2-3 weeks** for a solid MVP (vs. 2-4 months building from scratch)
- Leverages battle-tested distribution library
- Simpler deployment (one binary instead of two services + certs)
- Easier to reason about than separate auth service

### Key Advantages Over docker_auth + Distribution
- ✅ Single binary to deploy and manage
- ✅ No separate certificate/token signing key management
- ✅ No internal service networking setup
- ✅ Config stays simple (users and ACLs in one file)
- ✅ Traefik handles all TLS; your app is HTTP-only
- ✅ Can embed config into binary if desired (via `//go:embed`)

### Gotchas to Watch
- **Distribution library APIs are unstable**—the team warns against direct usage. You'll need to read source code and expect breaking changes between versions. Mitigate by pinning a stable version and forking if needed.[5]
- **JWT signing**: Don't lose your private key; store it securely or regenerate on startup and publish the public cert to clients.
- **Glob matching**: Test edge cases carefully (empty namespace, double wildcards, etc.).

This approach aligns with how Gitea integrates distribution—they import the library, wrap it with their auth layer, and expose it via HTTP routes in the main binary.[3][4]

[1](https://distribution.github.io/distribution/)
[2](https://vane.pl/build-and-run-docker-registry-from-sources)
[3](https://pkg.go.dev/code.gitea.io/gitea/routers/api/packages)
[4](https://conformance.opencontainers.org/static/v1.0/instructions/gitea/)
[5](https://pkg.go.dev/github.com/distribution/distribution)
[6](https://github.com/cesanta/docker_auth)
[7](https://xor22h.dev/deploying-docker-registry-with-acl-tls-and-s3/)
[8](https://docs.docker.com/reference/api/registry/auth/)
[9](https://distribution.github.io/distribution/spec/auth/jwt/)
[10](https://blog.mayflower.de/5650-Running-a-secure-docker-registry.html)
[11](https://docs.gitea.com/administration/reverse-proxies)
[12](https://martinheinz.dev/blog/6)
[13](https://labex.io/tutorials/go-how-to-embed-static-assets-in-golang-applications-421515)
[14](https://stackoverflow.com/questions/72859921/how-to-write-docker-private-registry-reverse-proxy-via-golang)
[15](https://dev.to/cwprogram/kubernetes-private-registry-with-registry-and-docker-auth-403i)
[16](https://pkg.go.dev/github.com/thelinuxkid/distribution)
[17](https://docs.docker.com/guides/golang/build-images/)
[18](https://www.docker.com/blog/how-to-use-your-own-registry-2/)
[19](https://github.com/kluctl/go-embed-python)
[20](https://docs.seqera.io/platform-cloud/credentials/gitea_registry_credentials)
[21](https://www.youtube.com/watch?v=B3J22RRb7rE)
[22](https://docs.gitea.com/usage/packages/go)
[23](https://www.it-experts.at/blog/posts/gitea.html)
[24](https://docs.gitea.com/installation/install-from-source)
[25](https://docs.gitea.com/installation/install-with-docker)
[26](https://github.com/go-gitea/gitea)
[27](https://docs.gitea.com/usage/packages/npm)
[28](https://docs.gitea.com/usage/packages/container)
[29](https://github.com/go-gitea/gitea/issues/31861)
[30](https://github.com/go-gitea/gitea/issues/19366)
[31](https://github.com/go-gitea/gitea/issues/29591)
[32](https://github.com/go-gitea/gitea/issues/31249)
[33](https://glasskube.dev/blog/container-image-registry-comparison/)
