#!/bin/sh
set -eu

VM_ROOT="${DEPFENCE_INTAKE_VM_ROOT:-$HOME/.depfence/vm/intake-v1}"
PID_FILE="$VM_ROOT/qemu.pid"
test -f "$PID_FILE" || exit 0
pid="$(cat "$PID_FILE")"
case "$pid" in *[!0-9]*|'') printf '%s\n' 'invalid QEMU pid file' >&2; exit 65 ;; esac
if kill -0 "$pid" 2>/dev/null; then
    kill "$pid"
    attempts=0
    while kill -0 "$pid" 2>/dev/null && test "$attempts" -lt 30; do
        sleep 1
        attempts=$((attempts + 1))
    done
    kill -0 "$pid" 2>/dev/null && {
        printf '%s\n' 'VM did not stop cleanly' >&2
        exit 1
    }
fi
rm "$PID_FILE"
printf '%s\n' 'intake VM stopped'

