"""A reference gateway started by an adapter must not outlive the process that started it.

Adapters start integrations with start_new_session=True, so the terminal's SIGINT and a plain
SIGTERM/SIGKILL of the test runner do not reach them: an interrupted or killed run left
`ref_gateway.py ... --policy naive` behind. Each test runs the starter in its own process, ends
it the way a run ends abnormally, and checks the gateway is gone.
"""

import os
import signal
import subprocess
import sys
import textwrap
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

STARTER = textwrap.dedent("""
    import sys, time
    from pathlib import Path
    from gcl.enforce.adapters import ReferenceGateway, ReferenceMCPGateway
    from gcl.enforce.servers import MockModel, StandInScanner

    cls = {"http": ReferenceGateway, "mcp": ReferenceMCPGateway}[sys.argv[2]]
    ad = cls(sys.executable, Path(sys.argv[1]), "naive")
    with StandInScanner(ad.protocol) as sc, MockModel("ok") as m:
        ad.start(m, sc)
        print(ad.proc.pid, flush=True)
        if sys.argv[3] == "exit":
            sys.exit(0)             # leaves without ad.stop()
        time.sleep(300)
""")


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _gone_within(pid: int, s: float) -> bool:
    end = time.monotonic() + s
    while time.monotonic() < end:
        if not _alive(pid):
            return True
        time.sleep(0.1)
    return not _alive(pid)


def _run(tmp_path, kind: str, how: str):
    env = {**os.environ, "PYTHONPATH": ROOT}
    p = subprocess.Popen([sys.executable, "-c", STARTER, str(tmp_path), kind, how], env=env, cwd=ROOT,
                         stdout=subprocess.PIPE, text=True)
    gw = int(p.stdout.readline())
    return p, gw


@pytest.mark.parametrize("kind", ["http", "mcp"])
@pytest.mark.parametrize("how", ["exit", "sigterm", "sighup", "sigkill"])
def test_a_gateway_does_not_outlive_its_starter(tmp_path, kind, how):
    p, gw = _run(tmp_path, kind, how)
    try:
        assert _alive(gw)
        if how != "exit":
            p.send_signal({"sigterm": signal.SIGTERM, "sighup": signal.SIGHUP, "sigkill": signal.SIGKILL}[how])
        p.wait(timeout=30)
        assert _gone_within(gw, 15), f"{kind} gateway {gw} survived its starter ({how})"
    finally:
        if _alive(gw):
            os.killpg(gw, signal.SIGKILL)   # the leak this test exists to catch; do not pass it on
