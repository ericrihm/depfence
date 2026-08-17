#!/bin/sh
set -eu

test "$(uname -s)" = Linux
test "$(uname -m)" = aarch64
COSIGN_VERSION="3.0.2"
COSIGN_SHA256="17fd784737ca54d7d8a343c82da6c5d6dbdee971e66644d923d1b057fb97d7ed"
UV_VERSION="0.12.5"
UV_SHA256="9bf43b4d1a07665bf64d4c4e710930b382321a785e0eb10aac07f46471f86a31"

sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
    ca-certificates curl docker-compose-v2 docker.io gnupg jq python3 python3-venv
curl -fsSL https://gvisor.dev/archive.key \
    | sudo gpg --dearmor --yes -o /usr/share/keyrings/gvisor-archive-keyring.gpg
printf '%s\n' \
    "deb [arch=arm64 signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
    | sudo tee /etc/apt/sources.list.d/gvisor.list >/dev/null
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends runsc
sudo runsc install
sudo systemctl restart docker
sudo usermod -aG docker depfence

temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
curl --fail --location --proto '=https' --tlsv1.2 \
    --output "$temporary/cosign" \
    "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-arm64"
printf '%s  %s\n' "$COSIGN_SHA256" "$temporary/cosign" | sha256sum --check
sudo install -o root -g root -m 0755 "$temporary/cosign" /usr/local/bin/cosign
curl --fail --location --proto '=https' --tlsv1.2 \
    --output "$temporary/uv.tar.gz" \
    "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/uv-aarch64-unknown-linux-gnu.tar.gz"
printf '%s  %s\n' "$UV_SHA256" "$temporary/uv.tar.gz" | sha256sum --check
tar -xzf "$temporary/uv.tar.gz" -C "$temporary"
sudo install -o root -g root -m 0755 \
    "$temporary/uv-aarch64-unknown-linux-gnu/uv" /usr/local/bin/uv
sudo install -o root -g root -m 0755 \
    "$temporary/uv-aarch64-unknown-linux-gnu/uvx" /usr/local/bin/uvx

sudo docker info --format '{{json .Runtimes}}' | jq -e 'has("runsc")' >/dev/null
sudo docker run --rm --runtime=runsc --network=none --read-only \
    --cap-drop=ALL --security-opt=no-new-privileges \
    hello-world >/dev/null
{
    printf '{"schema_version":"depfence.intake-guest/v1","architecture":"%s"' "$(uname -m)"
    printf ',"docker":"%s"' "$(docker --version | sed 's/"/\\"/g')"
    printf ',"runsc":"%s"' "$(runsc --version | head -1 | sed 's/"/\\"/g')"
    printf ',"cosign":"%s"' "$(cosign version 2>/dev/null | awk '/GitVersion/ {print $2; exit}')"
    printf ',"uv":"%s"}\n' "$(uv --version | awk '{print $2}')"
} | sudo tee /var/lib/depfence-intake-bootstrap.json >/dev/null
printf '%s\n' 'Guest bootstrap complete; log out and reconnect for docker-group membership.'
