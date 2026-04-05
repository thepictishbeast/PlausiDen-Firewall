# PlausiDen Firewall — development commands

# Run all tests
test:
    cargo test

# Run tests with output
test-verbose:
    cargo test -- --nocapture

# Check formatting and lints
check:
    cargo fmt --all -- --check
    cargo clippy -- -D warnings

# Format code
fmt:
    cargo fmt --all

# Build in release mode
build:
    cargo build --release

# Run security audit
audit:
    cargo audit
    cargo deny check advisories sources

# Clean build artifacts
clean:
    cargo clean
