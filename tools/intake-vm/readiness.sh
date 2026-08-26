#!/bin/sh
set -eu

: "${DEPFENCE_INTAKE_IMAGE:?set the signed intake image NAME@sha256:DIGEST}"
: "${DEPFENCE_ANALYZER_IMAGE:?set the signed static image NAME@sha256:DIGEST}"
: "${DEPFENCE_RENDER_IMAGE:?set the signed render image NAME@sha256:DIGEST}"
: "${DEPFENCE_CERTIFICATE_IDENTITY:?set the exact reviewed-main GitHub workflow identity}"
: "${DEPFENCE_SOURCE_COMMIT:?set the exact reviewed 40- or 64-hex source commit}"

SOURCE_ROOT="${DEPFENCE_SOURCE_ROOT:-$(pwd)}"
TEST_HOST="${DEPFENCE_ALLOWED_TEST_HOST:-github.com}"
TEST_URL="${DEPFENCE_ALLOWED_TEST_URL:-https://github.com/}"
STATE_ROOT="${DEPFENCE_READINESS_ROOT:-$HOME/.depfence/readiness/v1}"
NETWORK="depfence-acquisition"
PROXY="http://allowlist-proxy:3128"
ISSUER="https://token.actions.githubusercontent.com"
SIGNER="https://github.com/ericrihm/depfence/.github/workflows/publish-analysis-images.yml@refs/heads/main"

test "$DEPFENCE_CERTIFICATE_IDENTITY" = "$SIGNER" || {
    printf '%s\n' 'unexpected worker signing identity' >&2
    exit 64
}
case "$DEPFENCE_SOURCE_COMMIT" in
    *[!0-9a-fA-F]*|'') printf '%s\n' 'source commit must be hexadecimal' >&2; exit 64 ;;
esac
test "${#DEPFENCE_SOURCE_COMMIT}" = 40 || test "${#DEPFENCE_SOURCE_COMMIT}" = 64 || exit 64
case "$DEPFENCE_INTAKE_IMAGE $DEPFENCE_ANALYZER_IMAGE $DEPFENCE_RENDER_IMAGE" in
    *'@sha256:'*) ;;
    *) printf '%s\n' 'worker images must be digest pinned' >&2; exit 64 ;;
esac
test -f "$SOURCE_ROOT/uv.lock"
test -f "$SOURCE_ROOT/containers/compose.acquisition.yml"
umask 077
mkdir -p "$STATE_ROOT"
printf '%s\n' "$TEST_HOST" > "$STATE_ROOT/allowed-domains.txt"

cd "$SOURCE_ROOT"
uv sync --frozen --no-dev
cosign verify \
    --certificate-identity "$SIGNER" \
    --certificate-oidc-issuer "$ISSUER" \
    "$DEPFENCE_INTAKE_IMAGE" > "$STATE_ROOT/intake-signature.json"
cosign verify \
    --certificate-identity "$SIGNER" \
    --certificate-oidc-issuer "$ISSUER" \
    "$DEPFENCE_ANALYZER_IMAGE" > "$STATE_ROOT/analyzer-signature.json"
cosign verify \
    --certificate-identity "$SIGNER" \
    --certificate-oidc-issuer "$ISSUER" \
    "$DEPFENCE_RENDER_IMAGE" > "$STATE_ROOT/render-signature.json"
for signed_image in "$DEPFENCE_INTAKE_IMAGE" "$DEPFENCE_ANALYZER_IMAGE" "$DEPFENCE_RENDER_IMAGE"; do
    cosign verify-attestation --type slsaprovenance \
        --certificate-identity "$SIGNER" --certificate-oidc-issuer "$ISSUER" \
        "$signed_image" >/dev/null
    cosign verify-attestation --type spdxjson \
        --certificate-identity "$SIGNER" --certificate-oidc-issuer "$ISSUER" \
        "$signed_image" >/dev/null
done
docker pull "$DEPFENCE_INTAKE_IMAGE" >/dev/null
docker pull "$DEPFENCE_ANALYZER_IMAGE" >/dev/null
docker pull "$DEPFENCE_RENDER_IMAGE" >/dev/null
for reviewed_image in "$DEPFENCE_INTAKE_IMAGE" "$DEPFENCE_ANALYZER_IMAGE" "$DEPFENCE_RENDER_IMAGE"; do
    test "$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$reviewed_image")" = "$DEPFENCE_SOURCE_COMMIT"
    test "$(docker image inspect --format '{{.Config.User}}' "$reviewed_image")" = "65532:65532"
    test "$(docker image inspect --format '{{json .Config.Entrypoint}}' "$reviewed_image")" = '["/usr/local/bin/depfence-worker-entrypoint"]'
done

DEPFENCE_PROXY_ALLOWLIST="$STATE_ROOT/allowed-domains.txt" \
    docker compose -f containers/compose.acquisition.yml up -d --build
cleanup() {
    DEPFENCE_PROXY_ALLOWLIST="$STATE_ROOT/allowed-domains.txt" \
        docker compose -f containers/compose.acquisition.yml down --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

uv run depfence intake doctor \
    --intake-image "$DEPFENCE_INTAKE_IMAGE" \
    --analyzer-image "$DEPFENCE_ANALYZER_IMAGE" \
    --runtime runsc \
    --acquisition-network "$NETWORK" \
    --https-proxy "$PROXY" > "$STATE_ROOT/doctor.json"

DEPFENCE_ACQUISITION_NETWORK="$NETWORK" \
DEPFENCE_HTTPS_PROXY="$PROXY" \
DEPFENCE_OCI_RUNTIME=runsc \
DEPFENCE_INTAKE_IMAGE="$DEPFENCE_INTAKE_IMAGE" \
DEPFENCE_ALLOWED_TEST_URL="$TEST_URL" \
    containers/egress-proxy/containment-canary.sh > "$STATE_ROOT/egress-canary.txt"

for specification in \
    "intake:$DEPFENCE_INTAKE_IMAGE:containers/seccomp-intake.json" \
    "static:$DEPFENCE_ANALYZER_IMAGE:containers/seccomp-analysis.json" \
    "render:$DEPFENCE_RENDER_IMAGE:containers/seccomp-render.json"
do
    role="${specification%%:*}"
    remainder="${specification#*:}"
    image="${remainder%:*}"
    profile="${remainder##*:}"
    docker run --rm --runtime runsc --network none --read-only \
        --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges \
        --security-opt "seccomp=$SOURCE_ROOT/$profile" \
        --pids-limit 64 --memory 768m --cpus 1 \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,size=268435456 \
        "$image" --self-test > "$STATE_ROOT/$role-self-test.json"
done

test "$(docker ps -aq --filter label=dev.depfence.purpose=sealed-intake | wc -l | tr -d ' ')" = 0
test "$(docker ps -aq --filter label=dev.depfence.purpose=sealed-resolution | wc -l | tr -d ' ')" = 0
test "$(docker volume ls -q --filter label=dev.depfence.purpose=sealed-intake | wc -l | tr -d ' ')" = 0

{
    docker version --format '{{json .}}'
    runsc --version
    cosign version
    uv --version
    uname -a
    sha256sum uv.lock containers/seccomp-intake.json containers/seccomp-analysis.json containers/seccomp-render.json
} > "$STATE_ROOT/toolchain.txt"

jq -n \
    --arg status READY_FOR_URL \
    --arg intake_image "$DEPFENCE_INTAKE_IMAGE" \
    --arg analyzer_image "$DEPFENCE_ANALYZER_IMAGE" \
    --arg render_image "$DEPFENCE_RENDER_IMAGE" \
    --arg signer "$SIGNER" \
    --arg source_commit "$DEPFENCE_SOURCE_COMMIT" \
    --arg test_host "$TEST_HOST" \
    --slurpfile doctor "$STATE_ROOT/doctor.json" \
    '{schema_version:"depfence.intake-readiness/v1",status:$status,intake_image:$intake_image,analyzer_image:$analyzer_image,render_image:$render_image,signer_identity:$signer,source_commit:$source_commit,runtime:"runsc",acquisition_network:"depfence-acquisition",test_host:$test_host,doctor:$doctor[0],host_materialization:false}' \
    > "$STATE_ROOT/readiness.json"
chmod 600 "$STATE_ROOT"/*
cat "$STATE_ROOT/readiness.json"

