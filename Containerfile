# Build stage: compile the Rust binary on UBI10
FROM registry.access.redhat.com/ubi10/ubi:latest AS builder
WORKDIR /src

# Install Rust toolchain and build dependencies
RUN <<EORUN
set -xeuo pipefail
dnf -y install gcc make git-core openssl-devel
# Install rustup and stable toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
EORUN

# Copy source and build
COPY . .
RUN <<EORUN
set -xeuo pipefail
source $HOME/.cargo/env
cargo build --release --locked
mkdir -p /out/usr/bin
install -m 0755 target/release/service-gator /out/usr/bin/
EORUN

# Download CLI tools that service-gator wraps (not available in UBI)
FROM registry.access.redhat.com/ubi10/ubi:latest AS tools
WORKDIR /tools
RUN <<EORUN
set -xeuo pipefail
dnf -y install tar gzip

# Determine architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64) ARCH_SUFFIX="amd64"; TEA_ARCH="linux-amd64" ;;
    aarch64) ARCH_SUFFIX="arm64"; TEA_ARCH="linux-arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# GitHub CLI
GH_VERSION="2.67.0"
curl -fsSL "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_${ARCH_SUFFIX}.tar.gz" | tar xz
install -m 0755 gh_${GH_VERSION}_linux_${ARCH_SUFFIX}/bin/gh /tools/

# GitLab CLI (glab)
GLAB_VERSION="1.81.0"
curl -fsSL "https://gitlab.com/gitlab-org/cli/-/releases/v${GLAB_VERSION}/downloads/glab_${GLAB_VERSION}_linux_${ARCH_SUFFIX}.tar.gz" | tar xz
install -m 0755 bin/glab /tools/

# Forgejo/Gitea CLI (tea)
TEA_VERSION="0.9.2"
curl -fsSL "https://dl.gitea.com/tea/${TEA_VERSION}/tea-${TEA_VERSION}-${TEA_ARCH}" -o /tools/tea
chmod +x /tools/tea
EORUN

# Runtime stage: minimal UBI10 image
FROM registry.access.redhat.com/ubi10/ubi-minimal:latest

# Copy the binary from builder
COPY --from=builder /out/usr/bin/service-gator /usr/bin/

# Copy CLI tools
COPY --from=tools /tools/gh /usr/bin/
COPY --from=tools /tools/glab /usr/bin/
COPY --from=tools /tools/tea /usr/bin/

ENTRYPOINT ["service-gator"]
