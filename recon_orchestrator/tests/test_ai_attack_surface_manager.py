"""Unit tests for the AI Attack Surface lifecycle in ContainerManager (Step 3).

Docker + the Ollama judge manager are mocked, so these run with no daemon:

    docker compose exec -T recon-orchestrator python -m unittest \
        tests.test_ai_attack_surface_manager -v

Focus: the ref-counted Ollama lease (start acquires, finish/stop releases,
exactly once), state lifecycle from container exit codes, and the phase-marker
parser (incl. the banner false-match regression).
"""
import asyncio
import glob
import os
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from docker.errors import NotFound

import container_manager as cm
from container_manager import ContainerManager
from models import AiAttackSurfaceStatus


def make_manager():
    with patch("container_manager.docker") as md:
        md.from_env.return_value = MagicMock()
        mgr = ContainerManager()
    mgr.client = MagicMock()
    mgr.local_llm_manager = MagicMock()
    # ensure_up returns a status-like object (base_url/available/warning attrs).
    llm_status = MagicMock()
    llm_status.base_url = "http://localhost:11434"
    llm_status.available = True
    llm_status.warning = None
    mgr.local_llm_manager.ensure_up.return_value = llm_status
    return mgr


def fake_container(status="running", cid="c0ffee", exit_code=0):
    c = MagicMock()
    c.status = status
    c.id = cid
    c.attrs = {"State": {"ExitCode": exit_code}}
    return c


def run(coro):
    return asyncio.run(coro)


class TestPhaseParser(unittest.TestCase):
    def setUp(self):
        self.mgr = make_manager()

    def test_banner_does_not_false_match_phase3(self):
        # Regression: "AI Attack Surface scan" contains "Attack" -> must NOT
        # trigger phase 3. Only explicit [Phase N] markers count.
        ev = self.mgr._parse_ai_attack_log_line(
            "[*] AI Attack Surface scan — tool=skeleton", None, None)
        self.assertIsNone(ev.phase_number)
        self.assertFalse(ev.is_phase_start)

    def test_explicit_markers_map_in_order(self):
        cases = [("[Phase 1] Safety / bounds", 1), ("[Phase 2] Target loading", 2),
                 ("[Phase 3] Attack (skeleton — no tool)", 3), ("[Phase 4] Findings", 4)]
        prev_phase = None
        for line, expected in cases:
            ev = self.mgr._parse_ai_attack_log_line(line, prev_phase, None)
            self.assertEqual(ev.phase_number, expected)
            self.assertTrue(ev.is_phase_start)
            prev_phase = ev.phase

    def test_same_phase_not_restart(self):
        ev = self.mgr._parse_ai_attack_log_line("[Phase 2] Target loading", "Target loading", 2)
        self.assertFalse(ev.is_phase_start)

    def test_levels(self):
        self.assertEqual(self.mgr._parse_ai_attack_log_line("[!] boom", None, None).level, "error")
        self.assertEqual(self.mgr._parse_ai_attack_log_line("[+] ok", None, None).level, "success")
        self.assertEqual(self.mgr._parse_ai_attack_log_line("[*] doing", None, None).level, "action")


class TestLlmLease(unittest.TestCase):
    def setUp(self):
        self.mgr = make_manager()

    def test_release_is_idempotent(self):
        from models import AiAttackSurfaceState
        state = AiAttackSurfaceState(project_id="p", run_id="r", llm_leased=True)
        self.mgr._release_llm(state)
        self.assertFalse(state.llm_leased)
        self.mgr._release_llm(state)  # second call must not release again
        self.mgr.local_llm_manager.release.assert_called_once()

    def test_release_noop_when_not_leased(self):
        from models import AiAttackSurfaceState
        state = AiAttackSurfaceState(project_id="p", run_id="r", llm_leased=False)
        self.mgr._release_llm(state)
        self.mgr.local_llm_manager.release.assert_not_called()

    def test_refresh_completion_releases_lease(self):
        from models import AiAttackSurfaceState
        state = AiAttackSurfaceState(project_id="p", run_id="r",
                                     status=AiAttackSurfaceStatus.RUNNING,
                                     container_id="c0ffee", llm_leased=True)
        self.mgr.client.containers.get.return_value = fake_container(status="exited", exit_code=0)
        self.mgr._refresh_ai_attack_state(state)
        self.assertEqual(state.status, AiAttackSurfaceStatus.COMPLETED)
        self.assertFalse(state.llm_leased)
        self.mgr.local_llm_manager.release.assert_called_once()

    def test_refresh_error_exit_code(self):
        from models import AiAttackSurfaceState
        state = AiAttackSurfaceState(project_id="p", run_id="r",
                                     status=AiAttackSurfaceStatus.RUNNING,
                                     container_id="c0ffee", llm_leased=True)
        self.mgr.client.containers.get.return_value = fake_container(status="exited", exit_code=1)
        self.mgr._refresh_ai_attack_state(state)
        self.assertEqual(state.status, AiAttackSurfaceStatus.ERROR)
        self.assertIn("code 1", state.error)
        self.assertFalse(state.llm_leased)


class TestStartStop(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.mgr = make_manager()
        self.mgr.client.containers.run.return_value = fake_container()

    def tearDown(self):
        for f in glob.glob("/tmp/redamon/ai_attack_p_*.json"):
            try:
                os.unlink(f)
            except OSError:
                pass

    async def _start(self, **cfg):
        base = {"tool": "skeleton", "targets": [], "bounds": {"judge_model": "qwen2.5:0.5b"},
                "roe_confirmed": True, "dry_run": False}
        base.update(cfg)
        return await self.mgr.start_ai_attack_surface(
            project_id="p", user_id="u", webapp_api_url="", run_config=base,
            ai_attack_path="/host/ai_attack_surface_scan")

    async def test_start_acquires_lease_and_runs(self):
        state = await self._start()
        self.assertEqual(state.status, AiAttackSurfaceStatus.RUNNING)
        self.assertTrue(state.llm_leased)
        self.mgr.local_llm_manager.ensure_up.assert_called_once_with("qwen2.5:0.5b")
        self.mgr.client.containers.run.assert_called_once()
        # network_mode host + the config env var must be set.
        kwargs = self.mgr.client.containers.run.call_args.kwargs
        self.assertEqual(kwargs["network_mode"], "host")
        self.assertIn("AI_ATTACK_CONFIG", kwargs["environment"])

    async def test_dry_run_does_not_acquire_lease(self):
        state = await self._start(dry_run=True, roe_confirmed=False)
        self.assertFalse(state.llm_leased)
        self.mgr.local_llm_manager.ensure_up.assert_not_called()

    async def test_no_judge_model_no_lease(self):
        state = await self._start(bounds={})
        self.assertFalse(state.llm_leased)
        self.mgr.local_llm_manager.ensure_up.assert_not_called()

    async def test_start_failure_releases_lease(self):
        self.mgr.client.containers.run.side_effect = RuntimeError("docker boom")
        state = await self._start()
        self.assertEqual(state.status, AiAttackSurfaceStatus.ERROR)
        self.assertFalse(state.llm_leased)  # lease freed despite the failure
        self.mgr.local_llm_manager.release.assert_called_once()

    async def test_stop_releases_lease_and_clears_state(self):
        state = await self._start()
        run_id = state.run_id
        self.mgr.client.containers.get.return_value = fake_container(status="running")
        stopped = await self.mgr.stop_ai_attack_surface("p", run_id)
        self.assertFalse(stopped.llm_leased)
        self.assertNotIn(run_id, self.mgr.ai_attack_states.get("p", {}))

    async def test_status_unknown_run_is_idle(self):
        state = await self.mgr.get_ai_attack_surface_status("nope", "nope")
        self.assertEqual(state.status, AiAttackSurfaceStatus.IDLE)

    async def test_running_count(self):
        await self._start()
        self.assertEqual(self.mgr.get_ai_attack_running_count(), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
