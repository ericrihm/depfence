"""Focused stress tests for high-concurrency paths."""

from __future__ import annotations

import asyncio
import sqlite3

import pytest

from depfence._private.autonomous import crawler


@pytest.mark.asyncio
async def test_crawler_handles_100_concurrent_runs_without_db_or_task_leaks(
    tmp_path,
    monkeypatch,
):
    original_connect = sqlite3.connect
    open_connections: set[sqlite3.Connection] = set()
    crawl_calls = 0

    class TrackedConnection(sqlite3.Connection):
        def close(self) -> None:
            open_connections.discard(self)
            super().close()

    def tracked_connect(*args, **kwargs):
        kwargs["factory"] = TrackedConnection
        conn = original_connect(*args, **kwargs)
        open_connections.add(conn)
        return conn

    async def fake_crawl_npm_recent(limit: int = 100) -> list[dict]:
        nonlocal crawl_calls
        call_id = crawl_calls
        crawl_calls += 1
        await asyncio.sleep(0)
        return [
            {
                "name": f"stresspkg-{call_id}",
                "version": "1.0.0",
                "description": "stable package",
            }
        ][:limit]

    monkeypatch.setattr(crawler, "_DB_PATH", tmp_path / "threat_intel.db")
    monkeypatch.setattr(crawler, "_INTEROP_EVENTS", tmp_path / "missing" / "events.jsonl")
    monkeypatch.setattr(crawler.sqlite3, "connect", tracked_connect)
    monkeypatch.setattr(crawler, "crawl_npm_recent", fake_crawl_npm_recent)

    tasks_before = {task for task in asyncio.all_tasks() if not task.done()}
    results = await asyncio.gather(
        *(crawler.run_crawl("npm", limit=1) for _ in range(100)),
        return_exceptions=True,
    )
    leaked_tasks = {
        task for task in asyncio.all_tasks()
        if not task.done() and task not in tasks_before
    }

    failures = [result for result in results if isinstance(result, BaseException)]
    assert failures == []
    assert results == [{"packages_checked": 1, "threats_found": 0}] * 100
    assert crawl_calls == 100
    assert leaked_tasks == set()
    assert open_connections == set()

    conn = original_connect(str(tmp_path / "threat_intel.db"))
    try:
        run_count = conn.execute("SELECT COUNT(*) FROM crawl_runs").fetchone()[0]
        result_count = conn.execute("SELECT COUNT(*) FROM crawl_results").fetchone()[0]
    finally:
        conn.close()

    assert run_count == 100
    assert result_count == 100
