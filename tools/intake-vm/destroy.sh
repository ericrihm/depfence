#!/bin/sh
set -eu

VM_ROOT="${DEPFENCE_INTAKE_VM_ROOT:-$HOME/.depfence/vm/intake-v1}"
test "${1:-}" = "--yes" || {
    printf '%s\n' 'usage: destroy.sh --yes' >&2
    exit 64
}
case "$VM_ROOT" in
    "$HOME/.depfence/vm/"*) ;;
    *) printf '%s\n' 'refusing VM root outside ~/.depfence/vm' >&2; exit 64 ;;
esac
test -f "$VM_ROOT/manifest.json" || {
    printf '%s\n' 'refusing unmarked VM directory' >&2
    exit 65
}
grep -q '"schema_version":"depfence.intake-vm/v1"' "$VM_ROOT/manifest.json"
test ! -f "$VM_ROOT/qemu.pid" || {
    printf '%s\n' 'stop the VM before destroying it' >&2
    exit 73
}
find "$VM_ROOT" -depth -delete
printf '%s\n' 'VM files removed; secure erasure is not claimed.'

