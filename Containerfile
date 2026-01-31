# Build stage: compile the Rust binary on UBI10
FROM registry.access.redhat.com/ubi10/ubi:latest AS builder
WORKDIR /src

# Install Rust toolchain and build dependencies
RUN dnf -y install cargo openssl-devel

# Copy source
COPY . .

# Fetch dependencies with network, cache cargo registry
RUN --mount=type=cache,target=/root/.cargo/registry cargo fetch

# Build with cached target directory; --frozen ensures lockfile isn't modified
RUN --mount=type=cache,target=/root/.cargo/registry --mount=type=cache,target=/src/target <<EORUN
set -xeuo pipefail
cargo build --release --frozen
mkdir -p /out/usr/bin
# Copy from cache mount to output
cp target/release/service-gator /out/usr/bin/
chmod 0755 /out/usr/bin/service-gator
EORUN

# Download CLI tools that service-gator wraps
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

# TODO update these via renovate

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
RUN <<EORUN
set -xeuo pipefail
# Needed for push proxying
microdnf -y install git-core
microdnf clean all
EORUN

COPY --from=tools /tools/* /usr/bin/

# And our built binary
COPY --from=builder /out/usr/bin/service-gator /usr/bin/

ENTRYPOINT ["service-gator"]
