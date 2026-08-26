#!/bin/sh
set -eu

VM_ROOT="${DEPFENCE_INTAKE_VM_ROOT:-$HOME/.depfence/vm/intake-v1}"
SSH_PORT="${DEPFENCE_INTAKE_VM_SSH_PORT:-22222}"
UBUNTU_RELEASE="20260814"
UBUNTU_BASE="https://cloud-images.ubuntu.com/releases/noble/release-${UBUNTU_RELEASE}"
UBUNTU_IMAGE="ubuntu-24.04-server-cloudimg-arm64.img"
UBUNTU_SIGNING_FINGERPRINT="D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81"

case "$VM_ROOT" in
    "$HOME"|/|"") printf '%s\n' 'refusing unsafe VM root' >&2; exit 64 ;;
esac
for command in curl gpg gpgv hdiutil qemu-img ssh-keygen; do
    command -v "$command" >/dev/null || {
        printf 'missing prerequisite: %s\n' "$command" >&2
        exit 69
    }
done

umask 077
mkdir -p "$VM_ROOT/downloads" "$VM_ROOT/seed"
chmod 700 "$VM_ROOT" "$VM_ROOT/downloads" "$VM_ROOT/seed"
test ! -e "$VM_ROOT/intake.qcow2" || {
    printf '%s\n' "VM already exists at $VM_ROOT" >&2
    exit 73
}

curl --fail --location --proto '=https' --tlsv1.2 \
    --output "$VM_ROOT/downloads/SHA256SUMS" "$UBUNTU_BASE/SHA256SUMS"
curl --fail --location --proto '=https' --tlsv1.2 \
    --output "$VM_ROOT/downloads/SHA256SUMS.gpg" "$UBUNTU_BASE/SHA256SUMS.gpg"
if test ! -f "$VM_ROOT/downloads/$UBUNTU_IMAGE"; then
    curl --fail --location --proto '=https' --tlsv1.2 \
        --output "$VM_ROOT/downloads/$UBUNTU_IMAGE" "$UBUNTU_BASE/$UBUNTU_IMAGE"
fi

GNUPGHOME="$VM_ROOT/gnupg"
export GNUPGHOME
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"
curl --fail --location --proto '=https' --tlsv1.2 \
    --get --data-urlencode 'op=get' \
    --data-urlencode "search=0x$UBUNTU_SIGNING_FINGERPRINT" \
    --output "$VM_ROOT/downloads/ubuntu-cloud-signing-key.asc" \
    https://keyserver.ubuntu.com/pks/lookup
gpg --batch --import "$VM_ROOT/downloads/ubuntu-cloud-signing-key.asc"
actual_fingerprint="$(gpg --batch --with-colons --fingerprint "$UBUNTU_SIGNING_FINGERPRINT" \
    | awk -F: '$1 == "fpr" {print $10; exit}')"
test "$actual_fingerprint" = "$UBUNTU_SIGNING_FINGERPRINT" || {
    printf '%s\n' 'Ubuntu signing-key fingerprint mismatch' >&2
    exit 65
}
gpgv --keyring "$GNUPGHOME/pubring.kbx" \
    "$VM_ROOT/downloads/SHA256SUMS.gpg" "$VM_ROOT/downloads/SHA256SUMS"
expected_line="$(grep "[ *]$UBUNTU_IMAGE\$" "$VM_ROOT/downloads/SHA256SUMS")"
test -n "$expected_line"
(cd "$VM_ROOT/downloads" && printf '%s\n' "$expected_line" | shasum -a 256 -c -)

ssh-keygen -q -t ed25519 -N '' -C depfence-intake-vm -f "$VM_ROOT/ssh_key"
public_key="$(cat "$VM_ROOT/ssh_key.pub")"
cat > "$VM_ROOT/seed/meta-data" <<EOF
instance-id: depfence-intake-v1
local-hostname: depfence-intake
EOF
cat > "$VM_ROOT/seed/user-data" <<EOF
#cloud-config
users:
  - name: depfence
    groups: [sudo]
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: true
    ssh_authorized_keys:
      - $public_key
ssh_pwauth: false
disable_root: true
package_update: false
EOF
hdiutil makehybrid -quiet -iso -joliet -default-volume-name cidata \
    -o "$VM_ROOT/seed.iso" "$VM_ROOT/seed"
qemu-img convert -f qcow2 -O qcow2 \
    "$VM_ROOT/downloads/$UBUNTU_IMAGE" "$VM_ROOT/intake.qcow2"
qemu-img resize "$VM_ROOT/intake.qcow2" 80G

cat > "$VM_ROOT/manifest.json" <<EOF
{"schema_version":"depfence.intake-vm/v1","ubuntu_release":"$UBUNTU_RELEASE","ubuntu_image":"$UBUNTU_IMAGE","ubuntu_signing_fingerprint":"$UBUNTU_SIGNING_FINGERPRINT","disk_gib":80,"memory_mib":8192,"cpus":6,"ssh_host":"127.0.0.1","ssh_port":$SSH_PORT,"shared_directories":false}
EOF
chmod 600 "$VM_ROOT/manifest.json" "$VM_ROOT/intake.qcow2" "$VM_ROOT/seed.iso"
printf 'Created verified intake VM at %s\n' "$VM_ROOT"
printf 'Start it with: DEPFENCE_INTAKE_VM_ROOT=%s tools/intake-vm/start.sh\n' "$VM_ROOT"


