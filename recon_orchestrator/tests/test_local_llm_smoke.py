"""
Smoke test against a LIVE recon-orchestrator.

Hits the real /local-llm/* HTTP endpoints (stdlib urllib only) to confirm the
routes are wired and return the expected JSON shape. It does NOT spawn Ollama or
pull a model (that is the heavy lifecycle gate, exercised manually / in the
integration harness), so it is fast and side-effect free: it only reads status.

Skips automatically if no orchestrator is reachable, so it is safe in CI.

    # from inside the container (localhost:8010 is the orchestrator itself):
    docker compose exec -T recon-orchestrator python -m unittest \
        tests.test_local_llm_smoke -v
"""
import json
import os
import unittest
import urllib.error
import urllib.request

ORCH_URL = os.environ.get("ORCH_SMOKE_URL", "http://localhost:8010")

_STATUS_KEYS = {
    "available", "running", "containerId", "baseUrl", "model",
    "modelPresent", "leases", "models", "warning",
}


def _reachable() -> bool:
    try:
        with urllib.request.urlopen(f"{ORCH_URL}/health", timeout=3) as r:
            return r.status == 200
    except (urllib.error.URLError, OSError):
        return False


@unittest.skipUnless(_reachable(), f"no orchestrator at {ORCH_URL}")
class TestLocalLlmSmoke(unittest.TestCase):
    def test_status_endpoint_shape(self):
        with urllib.request.urlopen(f"{ORCH_URL}/local-llm/status", timeout=5) as r:
            self.assertEqual(r.status, 200)
            body = json.loads(r.read().decode("utf-8"))
        self.assertEqual(set(body.keys()), _STATUS_KEYS)
        self.assertIsInstance(body["leases"], int)
        self.assertIsInstance(body["models"], list)
        self.assertTrue(str(body["baseUrl"]).startswith("http://"))

    def test_status_is_read_only(self):
        # Two status reads must not change the lease count (no side effects).
        def leases():
            with urllib.request.urlopen(f"{ORCH_URL}/local-llm/status", timeout=5) as r:
                return json.loads(r.read().decode("utf-8"))["leases"]
        self.assertEqual(leases(), leases())


if __name__ == "__main__":
    unittest.main(verbosity=2)
