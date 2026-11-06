"""Real PostgreSQL advisory-lock leadership with two concurrent processes (issue #39 item 9).

Skipped unless ``PORTREVEAL_TEST_PG_URL`` is set, or a local throwaway server can be started
from ``PORTREVEAL_TEST_PG_BIN`` (directory containing ``initdb`` / ``pg_ctl`` / ``psql``).

This is an isolated synthetic environment: no scans, no SMTP, no webhooks, no real networks.
"""
from __future__ import annotations

import multiprocessing as mp
import os
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text

pytestmark = pytest.mark.skipif(
    not os.environ.get("PORTREVEAL_TEST_PG_URL") and not os.environ.get("PORTREVEAL_TEST_PG_BIN"),
    reason="Set PORTREVEAL_TEST_PG_URL or PORTREVEAL_TEST_PG_BIN for real Postgres leadership tests",
)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _start_local_pg(bin_dir: Path) -> tuple[str, Path, subprocess.Popen]:
    """Throwaway Postgres on localhost; caller must stop it and remove the data dir."""
    data = Path(tempfile.mkdtemp(prefix="pr-pg-"))
    port = _free_port()
    initdb = bin_dir / "initdb"
    pg_ctl = bin_dir / "pg_ctl"
    subprocess.check_call([str(initdb), "-D", str(data), "-U", "postgres", "--auth=trust", "-A", "trust"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    conf = data / "postgresql.conf"
    conf.write_text(conf.read_text() + f"\nlisten_addresses = '127.0.0.1'\nport = {port}\n")
    log_file = data / "pg.log"
    subprocess.check_call(
        [str(pg_ctl), "-D", str(data), "-l", str(log_file), "-o", f"-p {port}", "start"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    url = f"postgresql+psycopg://postgres@127.0.0.1:{port}/postgres"
    # Wait until ready
    engine = create_engine(url)
    for _ in range(50):
        try:
            with engine.connect() as c:
                c.execute(text("SELECT 1"))
            break
        except Exception:
            time.sleep(0.1)
    else:
        raise RuntimeError(f"Postgres did not start; log:\n{log_file.read_text()}")
    engine.dispose()
    return url, data, pg_ctl


@pytest.fixture(scope="module")
def pg_url():
    if url := os.environ.get("PORTREVEAL_TEST_PG_URL"):
        yield url
        return
    bin_dir = Path(os.environ["PORTREVEAL_TEST_PG_BIN"])
    url, data, pg_ctl = _start_local_pg(bin_dir)
    try:
        yield url
    finally:
        subprocess.call([str(pg_ctl), "-D", str(data), "stop", "-m", "immediate"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        shutil.rmtree(data, ignore_errors=True)


def _worker(url: str, name: str, ticks: int, interval: float, out: mp.Queue, release_after: float | None):
    """Acquire leadership, insert tick rows, optionally release early (simulating owner death)."""
    from app.core import leader  # import in child (spawn-safe)

    leader.stop_failover_watch()
    leader._held = None
    leader._sqlite_owner = False
    engine = create_engine(url, pool_size=1, max_overflow=0)
    try:
        owned = leader.acquire_background_leadership(engine)
        out.put(("acquire", name, owned))
        if not owned:
            became = False

            def on_become():
                nonlocal became
                became = True

            leader.start_failover_watch(engine, on_become, interval_s=0.15)
            deadline = time.time() + 8
            while time.time() < deadline and not became:
                time.sleep(0.05)
            leader.stop_failover_watch()
            if not became:
                out.put(("no_failover", name))
                return
            out.put(("failover", name))
        with engine.begin() as conn:
            conn.execute(text(
                "CREATE TABLE IF NOT EXISTS leader_ticks ("
                "id serial PRIMARY KEY, worker text NOT NULL, t timestamptz DEFAULT now())"
            ))
        started = time.time()
        for _ in range(ticks):
            if release_after is not None and time.time() - started >= release_after:
                break
            with engine.begin() as conn:
                conn.execute(text("INSERT INTO leader_ticks(worker) VALUES (:w)"), {"w": name})
            time.sleep(interval)
        if release_after is not None:
            # Hard death: drop the session so Postgres releases the advisory lock.
            conn = leader._held
            leader._held = None
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
            out.put(("died", name))
            return
        leader.release_background_leadership()
        out.put(("done", name))
    except Exception as exc:
        out.put(("error", name, type(exc).__name__, str(exc)[:200]))
        raise
    finally:
        engine.dispose()


def test_two_workers_do_not_double_schedule_and_failover_works(pg_url):
    engine = create_engine(pg_url)
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE IF EXISTS leader_ticks"))
    engine.dispose()

    ctx = mp.get_context("spawn")
    q: mp.Queue = ctx.Queue()
    a = ctx.Process(target=_worker, args=(pg_url, "A", 6, 0.1, q, 0.35))
    b = ctx.Process(target=_worker, args=(pg_url, "B", 5, 0.1, q, None))
    a.start()
    time.sleep(0.15)
    b.start()
    a.join(timeout=12)
    b.join(timeout=12)
    if a.is_alive():
        a.terminate()
    if b.is_alive():
        b.terminate()
    a.join(timeout=2)
    b.join(timeout=2)
    assert not a.is_alive() and not b.is_alive()

    events = []
    # Drain with a short timeout so late child puts are not missed.
    try:
        while True:
            events.append(q.get(timeout=0.5))
    except Exception:
        pass
    assert not any(e[0] == "error" for e in events), events
    acquires = [e for e in events if e[0] == "acquire"]
    assert sum(1 for e in acquires if e[2]) == 1, events  # exactly one initial owner
    assert any(e[0] == "died" for e in events), events
    assert any(e[0] == "failover" for e in events), events

    engine = create_engine(pg_url)
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT worker, count(*) FROM leader_ticks GROUP BY worker")).all()
        by = {w: n for w, n in rows}
        total = conn.execute(text("SELECT count(*) FROM leader_ticks")).scalar()
    engine.dispose()
    assert total == sum(by.values())
    # A wrote while owning; B wrote only after failover (never dual-owner schedule).
    assert by.get("A", 0) >= 1 and by.get("B", 0) >= 1, (by, events)
