"""Pytest configuration for depfence test suite."""
from __future__ import annotations

import signal

# Suppress SIGURG at module-import time — the earliest possible moment.
#
# Python 3.13's asyncio.run() uses SIGURG internally to wake up the event
# loop's self-pipe.  When asyncio.run() is called from within Click's
# CliRunner (which redirects file descriptors), SIGURG can escape the event
# loop and kill the test process.  The default handler (SIG_DFL) on macOS
# terminates the process on SIGURG, which is wrong for a test suite that
# legitimately uses asyncio inside CLI invocations.
#
# This must be module-level (not inside pytest_configure) so it is in effect
# before pytest-asyncio installs its own event-loop machinery.
signal.signal(signal.SIGURG, signal.SIG_IGN)
