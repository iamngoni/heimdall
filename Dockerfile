# Stage 0: Build CSS
FROM node:22-slim AS css-builder
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci
COPY tailwind.config.js ./
COPY assets ./assets
COPY templates ./templates
RUN npm run build:css

# Stage 1: Build
FROM rust:1.88-bookworm AS builder

WORKDIR /app

# Cache dependencies
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && \
    mkdir -p src/bin && echo "fn main() {}" > src/bin/schema_gen.rs && \
    echo "fn main() {}" > src/bin/mcp.rs
RUN cargo build --release 2>/dev/null || true

# Copy source
COPY . .

# Copy built CSS from css-builder stage
COPY --from=css-builder /app/static/css/app.css /app/static/css/app.css

# Build schema_gen first, then generate PostgreSQL migrations before building heimdall
# (sqlx::migrate! is a compile-time macro — migrations must exist before build)
RUN cargo build --release --bin schema_gen
RUN ./target/release/schema_gen postgres
RUN cargo build --release --bin heimdall --bin heimdall-mcp

# Stage 2: Runtime
FROM debian:bookworm-slim

# Semgrep is a required runtime dependency of Heimdall's static analysis stage.
# See src/pipeline/static_analysis/semgrep.rs — the binary must be on PATH or
# the application will fail to start with a clear configuration error.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    curl \
    git \
    python3 \
    python3-pip \
    && pip3 install --no-cache-dir --break-system-packages semgrep \
    && rm -rf /var/lib/apt/lists/* \
    && semgrep --version

WORKDIR /app

COPY --from=builder /app/target/release/heimdall /app/heimdall
COPY --from=builder /app/target/release/heimdall-mcp /app/heimdall-mcp
COPY --from=builder /app/templates /app/templates
COPY --from=builder /app/static /app/static

ENV APP_HOST=0.0.0.0
ENV APP_PORT=8080

EXPOSE 8080

CMD ["/app/heimdall"]
