"""Root-level pytest configuration — loaded before any plugins are initialized.

Python 3.13 asyncio uses SIGURG internally to wake its event loop's self-pipe.
On macOS, the default SIGURG disposition (SIG_DFL) terminates the process.
When asyncio.run() is called from within Click's CliRunner (which redirects
file descriptors), SIGURG can escape the event loop and kill the test process
before pytest-asyncio's own handlers can catch it.

Suppressing SIGURG here — at the very earliest conftest load point, which
precedes all plugin initialization — prevents spurious process death.
"""
import signal as _signal
_signal.signal(_signal.SIGURG, _signal.SIG_IGN)
