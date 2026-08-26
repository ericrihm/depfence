#!/bin/sh
set -eu

: "${DEPFENCE_INTAKE_IMAGE:?set DEPFENCE_INTAKE_IMAGE to the locally built intake image}"
: "${DEPFENCE_ALLOWED_TEST_URL:?set an inert HTTPS URL on the allowlisted host}"

network="${DEPFENCE_ACQUISITION_NETWORK:-depfence-acquisition}"
proxy="${DEPFENCE_HTTPS_PROXY:-http://allowlist-proxy:3128}"
runtime="${DEPFENCE_OCI_RUNTIME:-runsc}"

probe='import os,sys,urllib.request
url=sys.argv[1]
try:
    with urllib.request.urlopen(url, timeout=10) as response:
        response.read(1)
except Exception:
    raise SystemExit(2)
'

if docker run --rm --runtime "$runtime" --network "$network" \
    --read-only --user 65532:65532 --cap-drop ALL \
    --security-opt no-new-privileges --pids-limit 32 --memory 128m --cpus 0.5 \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
    --entrypoint /opt/depfence/bin/python "$DEPFENCE_INTAKE_IMAGE" \
    -c "$probe" "$DEPFENCE_ALLOWED_TEST_URL"; then
    echo "FAIL: acquisition worker reached the internet without the proxy" >&2
    exit 1
fi

docker run --rm --runtime "$runtime" --network "$network" \
    --read-only --user 65532:65532 --cap-drop ALL \
    --security-opt no-new-privileges --pids-limit 32 --memory 128m --cpus 0.5 \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
    --env "HTTPS_PROXY=$proxy" --env "https_proxy=$proxy" \
    --entrypoint /opt/depfence/bin/python "$DEPFENCE_INTAKE_IMAGE" \
    -c "$probe" "$DEPFENCE_ALLOWED_TEST_URL"

if docker run --rm --runtime "$runtime" --network "$network" \
    --read-only --user 65532:65532 --cap-drop ALL \
    --security-opt no-new-privileges --pids-limit 32 --memory 128m --cpus 0.5 \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
    --env "HTTPS_PROXY=$proxy" --env "https_proxy=$proxy" \
    --entrypoint /opt/depfence/bin/python "$DEPFENCE_INTAKE_IMAGE" \
    -c "$probe" "https://example.com/"; then
    echo "FAIL: proxy allowed a host absent from the allowlist" >&2
    exit 1
fi

echo "PASS: direct egress denied, allowlisted proxy egress allowed, other host denied"


