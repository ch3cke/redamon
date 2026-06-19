"""
Integration tests for the /local-llm/* API route layer.

The recon-orchestrator image has no httpx, so FastAPI's TestClient is
unavailable. Instead we exercise the route coroutines directly (they wrap the
manager via asyncio.to_thread) against a faked manager. This verifies routing
behaviour, the to_thread offload, the dict shape returned to the webapp, and
the not-initialized 503 guard — without a web server.

    docker compose exec -T recon-orchestrator python -m unittest \
        tests.test_local_llm_api -v
"""
import asyncio
import unittest
from unittest.mock import MagicMock

from fastapi import HTTPException

import api
from local_llm_manager import LocalLlmStatus


def run(coro):
    return asyncio.run(coro)


class _FakeManager:
    def __init__(self):
        self.status = MagicMock(return_value=LocalLlmStatus(running=True, leases=0))
        self.ensure_up = MagicMock(
            return_value=LocalLlmStatus(available=True, running=True, model_present=True, leases=1)
        )
        self.release = MagicMock(return_value=LocalLlmStatus(available=False, running=False, leases=0))


class TestLocalLlmRoutes(unittest.TestCase):
    def setUp(self):
        self._saved = api.local_llm_manager
        self.fake = _FakeManager()
        api.local_llm_manager = self.fake

    def tearDown(self):
        api.local_llm_manager = self._saved

    # --- status --- #
    def test_status_returns_dict(self):
        out = run(api.local_llm_status())
        self.assertIsInstance(out, dict)
        self.assertIn("leases", out)
        self.fake.status.assert_called_once()

    def test_status_503_when_uninitialized(self):
        api.local_llm_manager = None
        with self.assertRaises(HTTPException) as ctx:
            run(api.local_llm_status())
        self.assertEqual(ctx.exception.status_code, 503)

    # --- ensure --- #
    def test_ensure_default_model(self):
        out = run(api.local_llm_ensure())
        self.assertTrue(out["available"])
        self.assertEqual(out["leases"], 1)
        self.fake.ensure_up.assert_called_once_with(None)

    def test_ensure_passes_model_through(self):
        run(api.local_llm_ensure(model="qwen2.5:0.5b"))
        self.fake.ensure_up.assert_called_once_with("qwen2.5:0.5b")

    def test_ensure_503_when_uninitialized(self):
        api.local_llm_manager = None
        with self.assertRaises(HTTPException) as ctx:
            run(api.local_llm_ensure())
        self.assertEqual(ctx.exception.status_code, 503)

    # --- release --- #
    def test_release_returns_dict(self):
        out = run(api.local_llm_release())
        self.assertEqual(out["leases"], 0)
        self.fake.release.assert_called_once()

    def test_release_503_when_uninitialized(self):
        api.local_llm_manager = None
        with self.assertRaises(HTTPException) as ctx:
            run(api.local_llm_release())
        self.assertEqual(ctx.exception.status_code, 503)


if __name__ == "__main__":
    unittest.main(verbosity=2)
