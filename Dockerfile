# Stage 1: Build
FROM rust:1.85-bookworm AS builder

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

# Build schema_gen first, then generate migrations before building heimdall
# (sqlx::migrate! is a compile-time macro — migrations must exist before build)
RUN cargo build --release --bin schema_gen
RUN ./target/release/schema_gen ${DB_DRIVER}
RUN cargo build --release --bin heimdall

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/heimdall /app/heimdall

ENV APP_HOST=0.0.0.0
ENV APP_PORT=8080

EXPOSE 8080

CMD ["/app/heimdall"]
