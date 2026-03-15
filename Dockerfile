# Stage 0: Build CSS
FROM node:22-slim AS css-builder
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --production
COPY tailwind.config.js ./
COPY assets ./assets
COPY templates ./templates
RUN npm run build:css

# Stage 1: Build
FROM rust:1.88-bookworm AS builder

WORKDIR /app

# Database driver for migration generation (postgres|sqlite|mysql|mongo)
ARG DB_DRIVER=postgres

# Cache dependencies
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && \
    mkdir -p src/bin && echo "fn main() {}" > src/bin/schema_gen.rs
RUN cargo build --release 2>/dev/null || true

# Copy source
COPY . .

# Copy built CSS from css-builder stage
COPY --from=css-builder /app/static/css/app.css /app/static/css/app.css

# Build schema_gen first, then generate migrations before building heimdall
# (sqlx::migrate! is a compile-time macro — migrations must exist before build)
RUN cargo build --release --bin schema_gen
RUN ./target/release/schema_gen ${DB_DRIVER}
RUN cargo build --release --bin heimdall

# Stage 2: Runtime
FROM debian:bookworm-slim

# Optional: install semgrep for enhanced static analysis
ARG INSTALL_SEMGREP=true

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    git \
    && if [ "$INSTALL_SEMGREP" = "true" ]; then \
        apt-get install -y python3 python3-pip && \
        pip3 install semgrep --break-system-packages; \
    fi \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/heimdall /app/heimdall
COPY --from=builder /app/templates /app/templates
COPY --from=builder /app/static /app/static

ENV APP_HOST=0.0.0.0
ENV APP_PORT=8080

EXPOSE 8080

CMD ["/app/heimdall"]
