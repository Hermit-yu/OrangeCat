# OrangeCatPanel — multi-stage reproducible build (panel).
# Build:  docker build --target panel -t orangecat-panel:latest .
# Run:    docker run --rm -p 8390:8390 orangecat-panel:latest

# ---- Stage 1: builder (Go toolchain) ----
FROM golang:1.26-alpine AS builder
WORKDIR /src
# Copy module files first for layer caching
COPY go.mod go.sum ./
RUN go mod download
# Copy all sources
COPY . .
# Static build, stripped, no CGO (sqlite via modernc is pure-Go)
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/ocp-panel ./panel/cmd/ocp-panel \
 && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/ocp-agent ./agent/cmd/ocp-agent \
 && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/ocp-sampler ./panel/cmd/ocp-sampler

# ---- Stage 2: runtime (scratch, non-root) ----
FROM scratch AS panel
COPY --from=builder /out/ocp-panel /usr/local/bin/ocp-panel
COPY --from=builder /out/ocp-agent /usr/local/bin/ocp-agent
COPY --from=builder /out/ocp-sampler /usr/local/bin/ocp-sampler
# Container: data/log live under /data (mounted writable volume).
ENV OCP_PANEL_SOCKET=/data/ocp-panel.sock \
    OCP_PANEL_AUDIT_PATH=/data/auth-audit.jsonl \
    OCP_PANEL_METRICS_DB=/data/metrics.db \
    OCP_PANEL_PASSWORD_FILE=/data/panel-password
VOLUME /data
# Run as non-root (UID 65532 = nobody on many distros; no shell needed)
USER 65532:65532
EXPOSE 8390
ENTRYPOINT ["/usr/local/bin/ocp-panel"]
CMD ["-addr", "0.0.0.0:8390", "-sock", "/data/ocp-panel.sock", "-password-file", "/data/panel-password", "-auth-audit-file", "/data/auth-audit.jsonl"]
