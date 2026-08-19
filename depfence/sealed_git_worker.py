"""Container-side workers for exact-commit sealed Git intake."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from collections.abc import Iterator
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

from depfence import __version__
from depfence.core.artifact_analysis import (
    FONT_SUFFIXES,
    MAX_ARTIFACT_BYTES,
    SUPPORTED_SUFFIXES,
    _read_regular_file,
    _run_bounded_subprocess,
    scan_artifact_bytes,
    summarize_font,
)
from depfence.core.scan_scope import (
    InputLimitError,
    MalformedInputError,
    ScanIncompleteError,
)

MAX_ANALYSIS_ARTIFACTS = 2_000
MAX_ANALYSIS_BYTES = 256 * 1024 * 1024
MAX_COLLECTION_FONTS = 64
MAX_SYMBOLIC_REF_LENGTH = 256
MAX_TREE_RECORD_BYTES = 16 * 1024
MAX_TREE_RECORDS = 100_000
MAX_TREE_BYTES = 512 * 1024 * 1024


def _environment() -> dict[str, str]:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_PAGER": "cat",
        # Prevent automatic lazy-fetching of missing promisor objects.
        # After a blob:none partial clone, ls-tree -l would otherwise
        # silently fetch all blobs just to report sizes, defeating
        # selective materialization.  Explicit fetches (cat-file blob
        # in _materialize_blob, batch-check in _batch_check_sizes)
        # override this with GIT_ALLOW_LAZY_FETCH=1 per call.
        "GIT_NO_LAZY_FETCH": "1",
    }
    # Set both casings to the approved URL so Git/libcurl cannot
    # honour a lowercase value baked into the image while the host
    # sets only uppercase (or vice-versa).
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy", "")
    no_proxy = os.environ.get("NO_PROXY") or os.environ.get("no_proxy", "")
    environment["HTTPS_PROXY"] = proxy
    environment["https_proxy"] = proxy
    environment["NO_PROXY"] = no_proxy
    environment["no_proxy"] = no_proxy
    return environment


def _git(arguments: list[str], *, binary: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            "git",
            "-c", "core.hooksPath=/dev/null",
            "-c", "core.fsmonitor=false",
            "-c", "filter.lfs.smudge=",
            "-c", "filter.lfs.required=false",
            "-c", "http.followRedirects=false",
            "-c", "protocol.file.allow=never",
            "-c", "protocol.ext.allow=never",
            "-c", "protocol.git.allow=never",
            "-c", "protocol.ssh.allow=never",
            "-c", "protocol.https.allow=always",
            "-c", "protocol.version=2",
            *arguments,
        ],
        capture_output=True,
        check=False,
        env=_environment(),
        text=not binary,
        timeout=180,
    )


def _iter_ls_tree(repository: Path, commit: str) -> Iterator[bytes]:
    """Stream and bound NUL-delimited tree records instead of buffering a tree."""
    command = [
        "git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
        "-c", "protocol.version=2", "-C", str(repository),
        "ls-tree", "-rlz", commit,
    ]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env=_environment())
    assert process.stdout is not None
    buffer = bytearray()
    records = total_bytes = 0
    try:
        while True:
            chunk = process.stdout.read(64 * 1024)
            if not chunk:
                break
            buffer.extend(chunk)
            while (separator := buffer.find(0)) >= 0:
                record = bytes(buffer[:separator])
                del buffer[:separator + 1]
                if len(record) > MAX_TREE_RECORD_BYTES:
                    raise InputLimitError("Git tree record exceeds its byte budget")
                records += 1
                if records > MAX_TREE_RECORDS:
                    raise InputLimitError("Git tree exceeds its file-count budget")
                try:
                    metadata, _name = record.split(b"\t", 1)
                    _mode, _kind, _oid, raw_size = metadata.split(b" ", 3)
                    # After blob:none with GIT_NO_LAZY_FETCH=1, git prints
                    # "-" (non-blob) or "BAD" (unresolved promisor blob)
                    # instead of a numeric size.  Treat any non-numeric value
                    # as unresolved (0) so callers can batch-resolve later.
                    try:
                        size = int(raw_size)
                    except ValueError:
                        size = 0
                except (TypeError, ValueError):
                    raise MalformedInputError("Git tree returned malformed data") from None
                total_bytes += max(size, 0)
                if total_bytes > MAX_TREE_BYTES:
                    raise InputLimitError("Git tree exceeds its expanded-byte budget")
                yield record
        if buffer:
            raise MalformedInputError("Git tree output was not NUL terminated")
        if process.wait(timeout=5):
            raise ScanIncompleteError("Git tree enumeration failed")
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)


def _batch_check_sizes(
    repository: Path, oids: list[tuple[str, str]], *, max_oids: int = 2000
) -> dict[str, int]:
    """Resolve blob sizes for a bounded set of OIDs via cat-file --batch-check.

    Returns a mapping from OID to size.  Missing or invalid objects are
    omitted.  Explicitly allows lazy-fetch for this call only so that
    promisor blobs can report their size from the remote pack index
    without fetching full content.
    """
    if not oids:
        return {}
    if len(oids) > max_oids:
        raise InputLimitError("blob size resolution exceeds its OID budget")
    env = _environment()
    env["GIT_NO_LAZY_FETCH"] = "0"
    env["GIT_ALLOW_LAZY_FETCH"] = "1"
    process = subprocess.Popen(
        ["git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.version=2",
         "-C", str(repository), "cat-file", "--batch-check=%(objectname) %(objectsize)"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env=env,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    sizes: dict[str, int] = {}
    try:
        for oid, _suffix in oids:
            process.stdin.write(oid.encode("ascii") + b"\n")
        process.stdin.close()
        for line in process.stdout:
            line = line.strip()
            if b" missing" in line:
                continue
            parts = line.split(b" ")
            if len(parts) == 2:
                try:
                    sizes[parts[0].decode("ascii")] = int(parts[1])
                except (ValueError, UnicodeDecodeError):
                    continue
        process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        process.kill()
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
    return sizes


def _materialize_blob(repository: Path, object_id: str, expected_size: int) -> bool:
    """Trigger a promisor fetch for one selected blob while discarding its bytes."""
    env = _environment()
    env["GIT_NO_LAZY_FETCH"] = "0"
    env["GIT_ALLOW_LAZY_FETCH"] = "1"
    process = subprocess.Popen(
        ["git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.version=2",
         "-C", str(repository), "cat-file", "blob", object_id],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env=env,
    )
    assert process.stdout is not None
    received = 0
    try:
        while True:
            chunk = process.stdout.read(min(64 * 1024, expected_size + 1 - received))
            if not chunk:
                break
            received += len(chunk)
            if received > expected_size:
                process.kill()
                return False
        return process.wait(timeout=30) == 0 and received == expected_size
    except subprocess.TimeoutExpired:
        process.kill()
        return False
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)


def _exact_commit(value: str) -> str:
    if not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", value):
        raise SystemExit("an exact commit is required")
    return value.casefold()


def _validated_source(source: str, allowed_host: str) -> str:
    if any(ord(character) < 33 or ord(character) == 127 for character in source):
        raise SystemExit("sealed source contains whitespace or control characters")
    parsed = urlparse(source)
    source_host = (parsed.hostname or "").casefold().rstrip(".")
    normalized_host = allowed_host.casefold().rstrip(".")
    if (
        parsed.scheme != "https"
        or source_host != normalized_host
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise SystemExit("source host does not match the sealed allowlist")
    return source_host


def resolve_main() -> None:
    """Resolve remote HEAD without downloading Git objects or packfiles."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--allowed-host", required=True)
    parser.add_argument("--no-redirects", action="store_true", required=True)
    parser.add_argument("--format", choices=["json"], required=True)
    args = parser.parse_args()
    source_host = _validated_source(args.source, args.allowed_host)
    command = [
        "git",
        "-c", "core.hooksPath=/dev/null",
        "-c", "core.fsmonitor=false",
        "-c", "http.followRedirects=false",
        "-c", "protocol.file.allow=never",
        "-c", "protocol.ext.allow=never",
        "-c", "protocol.git.allow=never",
        "-c", "protocol.ssh.allow=never",
        "-c", "protocol.https.allow=always",
        "ls-remote",
        "--symref",
        args.source,
        "HEAD",
    ]
    try:
        code, stdout, _stderr = _run_bounded_subprocess(
            command,
            b"",
            _environment(),
            60.0,
        )
    except (InputLimitError, ScanIncompleteError, subprocess.TimeoutExpired):
        raise SystemExit("sealed HEAD resolution failed") from None
    if code:
        raise SystemExit("sealed HEAD resolution failed")
    try:
        lines = stdout.decode("utf-8", errors="strict").splitlines()
    except UnicodeError:
        raise SystemExit("sealed HEAD resolution returned malformed output") from None
    symbolic_refs: list[str] = []
    commits: list[str] = []
    for line in lines:
        if line.startswith("ref: "):
            try:
                raw_ref, target = line[5:].split("\t", 1)
            except ValueError:
                raise SystemExit("sealed HEAD resolution returned malformed output") from None
            if target != "HEAD":
                raise SystemExit("sealed HEAD resolution returned an unexpected target")
            symbolic_refs.append(raw_ref)
        else:
            try:
                raw_commit, target = line.split("\t", 1)
            except ValueError:
                raise SystemExit("sealed HEAD resolution returned malformed output") from None
            if target != "HEAD":
                raise SystemExit("sealed HEAD resolution returned an unexpected target")
            commits.append(_exact_commit(raw_commit))
    if len(commits) != 1 or len(symbolic_refs) > 1:
        raise SystemExit("sealed HEAD resolution was missing or ambiguous")
    symbolic_ref = symbolic_refs[0] if symbolic_refs else ""
    if symbolic_ref:
        if (
            len(symbolic_ref) > MAX_SYMBOLIC_REF_LENGTH
            or not symbolic_ref.startswith("refs/heads/")
            or ".." in symbolic_ref
            or "@{" in symbolic_ref
            or symbolic_ref.endswith((".", "/"))
            or not re.fullmatch(r"refs/heads/[A-Za-z0-9._/+\-]{1,244}", symbolic_ref)
        ):
            raise SystemExit("sealed HEAD resolution returned an unsafe symbolic ref")
    output = {
        "schema_version": "depfence.sealed-resolution-worker/v1",
        "source_host": source_host,
        "symbolic_ref": symbolic_ref,
        "exact_commit": commits[0],
        "complete": True,
        "limitations": [],
    }
    sys.stdout.write(json.dumps(output, sort_keys=True, separators=(",", ":")))


def acquire_main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--allowed-host", required=True)
    parser.add_argument("--no-redirects", action="store_true", required=True)
    parser.add_argument("--no-checkout", action="store_true", required=True)
    parser.add_argument("--no-submodules", action="store_true", required=True)
    parser.add_argument("--no-lfs", action="store_true", required=True)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--artifact-budget", type=int, default=MAX_ANALYSIS_ARTIFACTS)
    parser.add_argument("--byte-budget", type=int, default=MAX_ANALYSIS_BYTES)
    args = parser.parse_args()
    commit = _exact_commit(args.commit)
    _validated_source(args.source, args.allowed_host)
    destination = Path(args.destination)
    if destination.exists() or destination.parent != Path("/quarantine"):
        raise SystemExit("sealed repository destination is invalid")
    object_format = "sha256" if len(commit) == 64 else "sha1"
    initialized = _git(["init", "--bare", f"--object-format={object_format}", str(destination)])
    if initialized.returncode:
        raise SystemExit("bare repository initialization failed")
    if not 1 <= args.artifact_budget <= MAX_ANALYSIS_ARTIFACTS:
        raise SystemExit("sealed artifact budget is invalid")
    if not 1 <= args.byte_budget <= MAX_ANALYSIS_BYTES:
        raise SystemExit("sealed byte budget is invalid")
    configured = _git(["-C", str(destination), "remote", "add", "origin", args.source])
    if configured.returncode:
        raise SystemExit("sealed remote configuration failed")
    _git(["-C", str(destination), "config", "remote.origin.promisor", "true"])
    _git(["-C", str(destination), "config", "remote.origin.partialclonefilter", "blob:none"])
    fetched = _git([
        "-C", str(destination), "fetch", "--depth=1", "--no-tags",
        "--filter=blob:none", "origin", commit,
    ])
    if fetched.returncode:
        raise SystemExit("exact commit acquisition failed")
    resolved = _git(["-C", str(destination), "rev-parse", "--verify", "FETCH_HEAD^{commit}"])
    if resolved.returncode or str(resolved.stdout).strip().casefold() != commit:
        raise SystemExit("acquired commit does not match the requested commit")
    selected = selected_bytes = 0
    try:
        # Collect supported-suffix candidates with unresolved sizes for
        # batch resolution.  GIT_NO_LAZY_FETCH=1 prevents ls-tree -l
        # from silently fetching all blobs; sizes come back as "-".
        candidates: list[tuple[str, str, int | None]] = []
        unresolved_oids: list[tuple[str, str]] = []
        for record in _iter_ls_tree(destination, commit):
            metadata, raw_name = record.split(b"\t", 1)
            mode, kind, raw_oid, raw_size = metadata.split(b" ", 3)
            suffix = PurePosixPath(raw_name.decode("utf-8", errors="surrogateescape")).suffix.casefold()
            if mode[:3] != b"100" or kind != b"blob" or suffix not in SUPPORTED_SUFFIXES:
                continue
            oid = raw_oid.decode("ascii")
            try:
                parsed_size: int | None = int(raw_size)
            except ValueError:
                # "-" (non-blob) or "BAD" (unresolved promisor blob)
                parsed_size = None
            if parsed_size is None:
                candidates.append((oid, suffix, None))
                unresolved_oids.append((oid, suffix))
            else:
                candidates.append((oid, suffix, parsed_size))

        # Batch-resolve sizes for blobs whose sizes were not locally
        # available (bounded to supported suffixes only).
        if unresolved_oids:
            resolved_sizes = _batch_check_sizes(destination, unresolved_oids)
            candidates = [
                (oid, sfx, resolved_sizes.get(oid, 0) if sz is None else sz)
                for oid, sfx, sz in candidates
            ]

        for oid, _sfx, size in candidates:
            if size is None:
                size = 0
            if size < 0 or size > MAX_ARTIFACT_BYTES:
                continue
            if selected >= args.artifact_budget or selected_bytes + size > args.byte_budget:
                continue
            if not _materialize_blob(destination, oid, size):
                raise SystemExit("selected blob acquisition is unsupported or incomplete")
            selected += 1
            selected_bytes += size
    except (InputLimitError, MalformedInputError, ScanIncompleteError):
        raise SystemExit("bounded Git tree selection failed") from None


def inventory_main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--format", choices=["json"], required=True)
    args = parser.parse_args()
    commit = _exact_commit(args.commit)
    repository = Path(args.repository)
    if repository != Path("/quarantine/repository") or not repository.is_dir():
        raise SystemExit("sealed repository path is invalid")
    digest = hashlib.sha256()
    counts = {
        "file_count": 0,
        "byte_count": 0,
        "regular_files": 0,
        "symlink_count": 0,
        "submodule_count": 0,
        "non_regular_count": 0,
    }
    suffix_counts: dict[str, int] = {}
    warning_codes: set[str] = set()
    has_unresolved_sizes = False
    try:
      records = _iter_ls_tree(repository, commit)
      for record in records:
        try:
            metadata, raw_name = record.split(b"\t", 1)
            mode, object_type, object_id, raw_size = metadata.split(b" ", 3)
            try:
                size = int(raw_size)
            except ValueError:
                # "-" (non-blob) or "BAD" (unresolved promisor blob)
                size = 0
                has_unresolved_sizes = True
        except (TypeError, ValueError):
            raise SystemExit("Git tree returned malformed inventory data") from None
        counts["file_count"] += 1
        counts["byte_count"] += size
        if mode.startswith(b"100") and object_type == b"blob":
            counts["regular_files"] += 1
        elif mode == b"120000":
            counts["symlink_count"] += 1
            warning_codes.add("symlink_present")
        elif mode == b"160000":
            counts["submodule_count"] += 1
            warning_codes.add("submodule_present")
        else:
            counts["non_regular_count"] += 1
            warning_codes.add("non_regular_entry")
        digest.update(mode + b"\0" + object_type + b"\0" + object_id + b"\0" + raw_size + b"\0" + raw_name + b"\0")
        name = raw_name.decode("utf-8", errors="surrogateescape")
        suffix = PurePosixPath(name).suffix.casefold()
        key = suffix if re.fullmatch(r"\.[a-z0-9]{1,16}", suffix) else "<none>"
        suffix_counts[key] = suffix_counts.get(key, 0) + 1
    except (InputLimitError, MalformedInputError, ScanIncompleteError):
        raise SystemExit("Git tree inventory failed") from None
    if has_unresolved_sizes:
        warning_codes.add("oversized_blob")
    output = {
        "commit": commit,
        "tree_sha256": digest.hexdigest(),
        **counts,
        "suffix_counts": dict(sorted(suffix_counts.items())),
        "warning_codes": sorted(warning_codes),
    }
    sys.stdout.write(json.dumps(output, sort_keys=True, separators=(",", ":")))


def _artifact_id(commit: str, raw_name: bytes) -> str:
    digest = hashlib.sha256(commit.encode("ascii") + b"\0" + raw_name).hexdigest()
    return f"sealed-artifact-sha256:{digest}"


def _sanitized_font_payloads(data: bytes, suffix: str) -> tuple[list[bytes], list[str]]:
    """Sanitize hostile font bytes with OTS before structural inspection."""

    executable = shutil.which("ots-sanitize")
    if not executable:
        return [], ["font_sanitizer_unavailable"]
    indexes = [0]
    if suffix == ".ttc":
        if len(data) < 12 or data[:4] != b"ttcf":
            return [], ["font_sanitization_failed"]
        count = int.from_bytes(data[8:12], "big")
        if count < 1 or count > MAX_COLLECTION_FONTS:
            return [], ["font_collection_limit"]
        indexes = list(range(count))
    elif suffix == ".woff2" and len(data) >= 8 and data[4:8] == b"ttcf":
        # WOFF2 collection: decompress to TTC first, then enumerate members.
        decompressor = shutil.which("woff2_decompress")
        if not decompressor:
            return [], ["font_collection_unsupported"]
        with tempfile.TemporaryDirectory(prefix="depfence-woff2-") as wd:
            src = Path(wd) / "input.woff2"
            src.write_bytes(data)
            os.chmod(src, 0o600)
            code, _, _ = _run_bounded_subprocess(
                [decompressor, str(src)],
                b"",
                {"PATH": os.environ.get("PATH", ""), "LANG": "C.UTF-8"},
                30.0,
            )
            ttc = src.with_suffix(".ttc")
            if code or not ttc.is_file():
                return [], ["font_collection_decompression_failed"]
            data = _read_regular_file(ttc)
            suffix = ".ttc"
        # Fall through to TTC handling above — re-enter.
        return _sanitized_font_payloads(data, suffix)

    outputs: list[bytes] = []
    with tempfile.TemporaryDirectory(prefix="depfence-font-") as raw_directory:
        directory = Path(raw_directory)
        source = directory / f"input{suffix}"
        source.write_bytes(data)
        os.chmod(source, 0o600)
        for index in indexes:
            destination = directory / f"sanitized-{index}.ttf"
            command = [executable, str(source), str(destination)]
            if len(indexes) > 1:
                command.append(str(index))
            code, _stdout, _stderr = _run_bounded_subprocess(
                command,
                b"",
                {"PATH": os.environ.get("PATH", ""), "LANG": "C.UTF-8"},
                30.0,
            )
            if code or not destination.is_file():
                return [], ["font_sanitization_failed"]
            outputs.append(_read_regular_file(destination))
    return outputs, []


def analyze_main() -> None:
    """Analyze supported blobs without checkout and emit redacted evidence only."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--format", choices=["json"], required=True)
    parser.add_argument(
        "--artifact-budget", type=int, default=MAX_ANALYSIS_ARTIFACTS
    )
    parser.add_argument("--byte-budget", type=int, default=MAX_ANALYSIS_BYTES)
    args = parser.parse_args()
    commit = _exact_commit(args.commit)
    if not 1 <= args.artifact_budget <= MAX_ANALYSIS_ARTIFACTS:
        raise SystemExit("sealed artifact budget is invalid")
    if not 1 <= args.byte_budget <= MAX_ANALYSIS_BYTES:
        raise SystemExit("sealed analysis byte budget is invalid")
    repository = Path(args.repository)
    if repository != Path("/quarantine/repository") or not repository.is_dir():
        raise SystemExit("sealed repository path is invalid")

    findings: list[dict[str, object]] = []
    limitations: list[dict[str, str]] = []
    coverage: dict[str, dict[str, int]] = {}
    font_groups: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    candidates = analyzed = analyzed_bytes = 0
    complete = True
    try:
      records = _iter_ls_tree(repository, commit)
      for record in records:
        try:
            metadata, raw_name = record.split(b"\t", 1)
            mode, object_type, object_id, raw_size = metadata.split(b" ", 3)
            # After blob:none with GIT_NO_LAZY_FETCH=1, sizes may be
            # unavailable ("-" or "BAD").  Use 0 as a placeholder and
            # verify actual size after cat-file retrieval.
            try:
                size = int(raw_size)
                size_resolved = True
            except ValueError:
                size = 0
                size_resolved = False
        except (TypeError, ValueError):
            raise SystemExit("Git tree returned malformed analysis data") from None
        name = raw_name.decode("utf-8", errors="surrogateescape")
        suffix = PurePosixPath(name).suffix.casefold()
        if mode[:3] != b"100" or object_type != b"blob" or suffix not in SUPPORTED_SUFFIXES:
            continue
        candidates += 1
        suffix_coverage = coverage.setdefault(suffix, {"total": 0, "analyzed": 0, "incomplete": 0})
        suffix_coverage["total"] += 1
        opaque_id = _artifact_id(commit, raw_name)
        if candidates > args.artifact_budget:
            complete = False
            suffix_coverage["incomplete"] += 1
            limitations.append({"artifact_id": opaque_id, "suffix": suffix, "code": "artifact_budget_exceeded"})
            continue
        if size_resolved and (size < 0 or size > MAX_ARTIFACT_BYTES or analyzed_bytes + size > args.byte_budget):
            complete = False
            suffix_coverage["incomplete"] += 1
            code = "artifact_size_exceeded" if size > MAX_ARTIFACT_BYTES else "analysis_byte_budget_exceeded"
            limitations.append({"artifact_id": opaque_id, "suffix": suffix, "code": code})
            continue
        # Explicitly allow lazy-fetch for blob retrieval — _git() inherits
        # GIT_NO_LAZY_FETCH=1 from _environment(), which blocks promisor
        # fetches.  Materialized blobs need the fetch to succeed.
        blob_env = _environment()
        blob_env["GIT_NO_LAZY_FETCH"] = "0"
        blob_env["GIT_ALLOW_LAZY_FETCH"] = "1"
        blob = subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.version=2",
             "-C", str(repository), "cat-file", "blob", object_id.decode("ascii")],
            capture_output=True, check=False, env=blob_env,
        )
        actual_size = len(blob.stdout) if isinstance(blob.stdout, bytes) else 0
        if not size_resolved:
            # Post-fetch budget enforcement when ls-tree size was unavailable
            if actual_size > MAX_ARTIFACT_BYTES or analyzed_bytes + actual_size > args.byte_budget:
                complete = False
                suffix_coverage["incomplete"] += 1
                code = "artifact_size_exceeded" if actual_size > MAX_ARTIFACT_BYTES else "analysis_byte_budget_exceeded"
                limitations.append({"artifact_id": opaque_id, "suffix": suffix, "code": code})
                continue
        expected = actual_size if not size_resolved else size
        if blob.returncode or not isinstance(blob.stdout, bytes) or len(blob.stdout) != expected:
            complete = False
            suffix_coverage["incomplete"] += 1
            limitations.append({"artifact_id": opaque_id, "suffix": suffix, "code": "blob_read_failed"})
            continue
        analyzed += 1
        analyzed_bytes += len(blob.stdout)
        suffix_coverage["analyzed"] += 1
        try:
            scan_payloads = [blob.stdout]
            scan_suffix = suffix
            fixed_limitations: list[str] = []
            if suffix in FONT_SUFFIXES:
                scan_payloads, fixed_limitations = _sanitized_font_payloads(
                    blob.stdout, suffix
                )
                scan_suffix = ".ttf"
            artifact_findings = []
            artifact_limitations = list(fixed_limitations)
            for scan_payload in scan_payloads:
                nested_findings, nested_limitations = scan_artifact_bytes(
                    Path(f"input{scan_suffix}"), scan_payload
                )
                artifact_findings.extend(nested_findings)
                artifact_limitations.extend(nested_limitations)
                if suffix in FONT_SUFFIXES:
                    summary = summarize_font(scan_payload)
                    if (
                        summary.complete
                        and summary.family
                        and summary.cmap_entries is not None
                        and summary.cmap_entries <= 8
                    ):
                        content_digest = hashlib.sha256(scan_payload).hexdigest()
                        font_groups[summary.family.casefold()].append(
                            (opaque_id, suffix, content_digest)
                        )
        except InputLimitError:
            artifact_findings, artifact_limitations = [], ["input_limit"]
        except MalformedInputError:
            artifact_findings, artifact_limitations = [], ["malformed_artifact"]
        except ScanIncompleteError:
            artifact_findings, artifact_limitations = [], ["analysis_incomplete"]
        if artifact_limitations:
            complete = False
            suffix_coverage["incomplete"] += 1
            fixed_codes = {
                "font_sanitizer_unavailable",
                "font_sanitization_failed",
                "font_collection_limit",
                "font_collection_unsupported",
                "font_collection_decompression_failed",
            }
            limitation_code = next(
                (value for value in artifact_limitations if value in fixed_codes),
                "deep_analysis_required",
            )
            limitations.append({
                "artifact_id": opaque_id,
                "suffix": suffix,
                "code": limitation_code,
            })
        for finding in artifact_findings[:16]:
            rule_id = str(finding.metadata.get("rule_id", ""))
            if rule_id not in {
                "DF-FONT-001", "DF-FONT-002", "DF-FONT-003", "DF-FONT-004", "DF-FONT-005",
                "DF-WEB-001",
                "DF-DOCX-001", "DF-DOCX-002",
                "DF-PDF-001", "DF-PDF-002", "DF-PDF-003",
            }:
                continue
            findings.append({
                "artifact_id": opaque_id,
                "suffix": suffix,
                "rule_id": rule_id,
                "severity": "medium",
                "confidence": round(float(finding.confidence), 6),
                "evidence_class": str(finding.metadata.get("evidence_class", "structural"))[:64],
            })
    except (InputLimitError, MalformedInputError, ScanIncompleteError):
        raise SystemExit("Git tree analysis inventory failed") from None

    for members in font_groups.values():
        # Require unique content — identical copies sharing a family name
        # should not inflate the cluster count.
        unique_digests = {digest for _oid, _sfx, digest in members}
        if len(unique_digests) < 8:
            continue
        opaque_id, suffix, _digest = members[0]
        findings.append({
            "artifact_id": opaque_id,
            "suffix": suffix,
            "rule_id": "DF-FONT-001",
            "severity": "medium",
            "confidence": 0.76,
            "evidence_class": "sparse_font_cluster",
        })

    output = {
        "schema_version": "depfence.sealed-analysis/v1",
        "commit": commit,
        "complete": complete,
        "candidate_count": candidates,
        "analyzed_count": analyzed,
        "analyzed_bytes": analyzed_bytes,
        "coverage_by_suffix": dict(sorted(coverage.items())),
        "findings": findings[:MAX_ANALYSIS_ARTIFACTS],
        "limitations": limitations[:MAX_ANALYSIS_ARTIFACTS],
        "toolchain": {"depfence": __version__},
    }
    sys.stdout.write(json.dumps(output, sort_keys=True, separators=(",", ":"), allow_nan=False))


if __name__ == "__main__":
    raise SystemExit("use a sealed Git worker console entry point")
