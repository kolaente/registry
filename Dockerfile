# Build stage
FROM golang:1.25-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a \
    -o registry \
    ./cmd/registry

# Final stage
FROM scratch

# Copy CA certificates for HTTPS
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy the binary
COPY --from=builder /build/registry /registry

# Create mount points
VOLUME ["/data/registry", "/data/keys"]

# Expose registry port
EXPOSE 5000

# Set default config path
ENV CONFIG_PATH=/etc/registry/config.yaml

# Run the registry
ENTRYPOINT ["/registry"]
CMD ["--config", "/etc/registry/config.yaml"]
