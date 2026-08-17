# Isolated worker images

These images are built from the single digest-pinned `containers/Dockerfile`:

- `intake` permits metadata-only `HEAD` resolution, exact-commit acquisition,
  and inventory. Resolution uses `git ls-remote` and fetches no objects.
- `static` permits offline Git inventory and bounded blob analysis and includes
  OTS and WOFF2 tooling.
- `render` permits only rendered PDF/DOCX comparison and includes LibreOffice,
  Poppler, Tesseract, Chromium, and a fixed system font.

The entrypoint is a command allowlist, not a shell. All images run as
`65532:65532`. Operators must also use a read-only root, dropped capabilities,
`no-new-privileges`, PID/memory/CPU/tmpfs limits, and the matching seccomp file.
Analysis uses `--network none`; only acquisition may receive a constrained
network.

Release images are published as immutable GHCR digests. The release workflow
attaches BuildKit SBOM and provenance attestations, signs each digest with
GitHub OIDC via Cosign, verifies the signature, and records the digest in the
workflow summary. Tags are discovery aids only; DepFence accepts digest-pinned
image references.

Local contract smoke test:

```sh
docker build --target intake -t depfence-intake:test -f containers/Dockerfile .
docker run --rm --network none --read-only --user 65532:65532 \
  --cap-drop ALL --security-opt no-new-privileges \
  --security-opt seccomp=containers/seccomp-intake.json \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m depfence-intake:test --self-test
```

No hostile or third-party artifact is used by the build or smoke tests.

## Acquisition network and HTTPS allowlist

The acquisition worker must not be attached directly to a normal bridge. The
provided Compose profile creates an internal `depfence-acquisition` network and
a dual-homed Squid proxy. The worker can reach the proxy but has no route to the
internet; the proxy permits CONNECT to port 443 only for exact hostnames in an
operator-supplied file and rejects private, loopback, link-local, documentation,
multicast, and reserved destination ranges.

```sh
allowlist="$(mktemp)"
printf '%s\n' 'github.com' > "$allowlist"
DEPFENCE_PROXY_ALLOWLIST="$allowlist" \
  docker compose -f containers/compose.acquisition.yml up -d --build

# Pass these exact values to `depfence fleet intake`:
# --acquisition-network depfence-acquisition
# --https-proxy http://allowlist-proxy:3128
```

Keep the allowlist file private and use bare exact hostnames; a leading dot
would allow subdomains. Before any hostile intake, run
`containers/egress-proxy/containment-canary.sh` with an inert URL on the allowed
host. It proves direct egress fails, allowlisted proxy egress succeeds, and a
non-allowlisted host fails. This is a containment canary, not a substitute for
the runtime (`runsc`/Kata), DNS, and destination-IP controls required in
production.

## Disposable local intake VM

The current macOS/OrbStack daemon exposes only `runc`, so it is suitable for
image builds but not hostile intake. The scripts under `tools/intake-vm/`
create a separate QEMU/HVF Ubuntu ARM64 VM with no shared directories and
loopback-only SSH.

```sh
tools/intake-vm/create.sh
tools/intake-vm/start.sh
scp -i ~/.depfence/vm/intake-v1/ssh_key -P 22222 \
  tools/intake-vm/bootstrap-guest.sh depfence@127.0.0.1:/tmp/
ssh -i ~/.depfence/vm/intake-v1/ssh_key -p 22222 depfence@127.0.0.1 \
  sh /tmp/bootstrap-guest.sh
```

After publishing v0.8.0, copy an archive of that exact release into the VM and
run `tools/intake-vm/readiness.sh` there with the signed intake/static image
digests. It verifies signatures, runs `intake doctor`, executes the proxy and
runtime canaries, checks for orphaned resources, and emits `READY_FOR_URL`.
Do not supply a hostile URL before that status is produced.
