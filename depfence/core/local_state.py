"""Private, machine-local state with an explicit boundary from Git worktrees."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path


class PrivateStateError(RuntimeError):
    """The requested local-state operation would weaken the privacy boundary."""


def _resolved(path: Path) -> Path:
    return path.expanduser().resolve(strict=False)


def _within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _reject_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if current.is_symlink():
            raise PrivateStateError(f"private state path contains symlink: {current}")


def _protect_directory_chain(root: Path, directory: Path) -> None:
    """Create and protect every private-state directory, not only the leaf."""

    if not _within(directory, root):
        raise PrivateStateError(f"private state directory escapes root: {directory}")
    os.chmod(root, 0o700)
    current = root
    for part in directory.relative_to(root).parts:
        current /= part
        if current.is_symlink():
            raise PrivateStateError(f"private state path contains symlink: {current}")
        current.mkdir(mode=0o700, exist_ok=True)
        os.chmod(current, 0o700)


@dataclass(frozen=True)
class PrivateState:
    """Own the only supported root for non-reviewable local DepFence state."""

    root: Path

    @classmethod
    def open(
        cls,
        *,
        project_root: Path | str,
        root: Path | str | None = None,
    ) -> PrivateState:
        project = _resolved(Path(project_root))
        requested = (
            Path(root).expanduser()
            if root is not None
            else Path.home() / ".depfence" / "private" / "v1"
        )
        if not requested.is_absolute():
            requested = Path.cwd() / requested
        _reject_symlink_components(requested)
        destination = _resolved(requested)
        if _within(destination, project):
            raise PrivateStateError(
                f"private state must be outside the project worktree: {destination}"
            )
        destination.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(destination, 0o700)
        return cls(destination)

    def path(self, relative: str | Path) -> Path:
        raw = Path(relative)
        if raw.is_absolute() or ".." in raw.parts:
            raise PrivateStateError(f"private state path must be relative: {relative}")
        requested = self.root / raw
        _reject_symlink_components(requested)
        destination = _resolved(requested)
        if not _within(destination, self.root):
            raise PrivateStateError(f"private state path escapes root: {relative}")
        return destination

    def _install_key(self) -> bytes:
        key_path = self.path("install.key")
        if key_path.exists():
            os.chmod(key_path, 0o600)
            key = key_path.read_bytes()
            if len(key) != 32:
                raise PrivateStateError("private install key has an invalid length")
            return key
        key_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(key_path.parent, 0o700)
        key = secrets.token_bytes(32)
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(key_path, flags, 0o600)
        except FileExistsError:
            # Another scanner process won the installation race. Its key is
            # the canonical one; never overwrite it with this process's key.
            if key_path.is_symlink():
                raise PrivateStateError("private install key is a symlink") from None
            os.chmod(key_path, 0o600)
            installed = key_path.read_bytes()
            if len(installed) != 32:
                raise PrivateStateError("private install key has an invalid length") from None
            return installed
        try:
            os.fchmod(descriptor, stat.S_IRUSR | stat.S_IWUSR)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(key)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            try:
                key_path.unlink()
            except FileNotFoundError:
                pass
            raise
        return key

    def project_id(self, project_root: Path | str) -> str:
        """Return an opaque stable identifier without persisting a cleartext path."""
        return self.opaque_id("project", _resolved(Path(project_root)))

    def opaque_id(self, namespace: str, value: Path | str) -> str:
        """Return a namespaced HMAC identifier for sensitive machine-local values."""
        if not namespace or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789_-" for character in namespace):
            raise PrivateStateError("opaque identifier namespace is invalid")
        message = namespace.encode("ascii") + b"\0" + os.fsencode(value)
        digest = hmac.new(self._install_key(), message, hashlib.sha256).hexdigest()
        if namespace == "project":
            return f"project-hmac-sha256:{digest}"
        return f"{namespace}-hmac-sha256:{digest}"

    def write_text(self, relative: str | Path, value: str) -> Path:
        return self.write_bytes(relative, value.encode("utf-8"))

    def write_bytes(self, relative: str | Path, value: bytes) -> Path:
        destination = self.path(relative)
        _protect_directory_chain(self.root, destination.parent)
        if destination.is_symlink():
            raise PrivateStateError(f"refusing to replace symlink: {destination}")

        descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
        temporary_path = Path(temporary)
        try:
            os.fchmod(descriptor, stat.S_IRUSR | stat.S_IWUSR)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(value)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, destination)
            os.chmod(destination, 0o600)
        except BaseException:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass
            raise
        return destination


