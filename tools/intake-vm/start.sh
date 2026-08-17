#!/bin/sh
set -eu

VM_ROOT="${DEPFENCE_INTAKE_VM_ROOT:-$HOME/.depfence/vm/intake-v1}"
SSH_PORT="${DEPFENCE_INTAKE_VM_SSH_PORT:-22222}"
QEMU_PREFIX="${QEMU_PREFIX:-$(brew --prefix qemu)}"
QEMU="$QEMU_PREFIX/bin/qemu-system-aarch64"
FIRMWARE="$QEMU_PREFIX/share/qemu/edk2-aarch64-code.fd"

test -f "$VM_ROOT/intake.qcow2"
test -f "$VM_ROOT/seed.iso"
test -f "$FIRMWARE"
if test -f "$VM_ROOT/qemu.pid" && kill -0 "$(cat "$VM_ROOT/qemu.pid")" 2>/dev/null; then
    printf '%s\n' 'intake VM is already running' >&2
    exit 73
fi

"$QEMU" \
    -name depfence-intake-v1 \
    -machine virt,highmem=on \
    -accel hvf \
    -cpu host \
    -smp 6 \
    -m 8192 \
    -bios "$FIRMWARE" \
    -drive "if=virtio,file=$VM_ROOT/intake.qcow2,format=qcow2,cache=none" \
    -drive "if=virtio,file=$VM_ROOT/seed.iso,format=raw,readonly=on" \
    -device virtio-net-pci,netdev=vmnet \
    -netdev "user,id=vmnet,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22" \
    -device virtio-rng-pci \
    -display none \
    -monitor none \
    -serial "file:$VM_ROOT/serial.log" \
    -pidfile "$VM_ROOT/qemu.pid" \
    -daemonize

printf 'VM started. SSH: ssh -i %s -p %s depfence@127.0.0.1\n' "$VM_ROOT/ssh_key" "$SSH_PORT"
