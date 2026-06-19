"""Integration tests against a LIVE Neo4j.

Exercises the real driver path: target loader reads seeded AI endpoints, the
normalizer writes a Vulnerability and links it via HAS_VULNERABILITY, re-runs
dedup on the deterministic id, and the BaseURL fallback fires when no Endpoint
matches. Uses an isolated project id and cleans up before/after.

Skips automatically when no Neo4j is reachable, so it is safe in CI. Run with
the Neo4j creds in env and host networking:

    docker run --rm --network host \
      -e NEO4J_URI=bolt://localhost:7687 -e NEO4J_USER=neo4j -e NEO4J_PASSWORD=changeme123 \
      -v "$PWD/ai_attack_surface_scan:/app/ai_attack_surface_scan" \
      redamon-ai-attack-surface:latest \
      python -m unittest ai_attack_surface_scan.tests.test_integration_graph -v
"""
import unittest

import graph
import target_loader as tl
from normalizer import Finding, finding_id, make_dummy_finding, write_finding

UID = "aiatk-itest-user"
PID = "aiatk-itest-proj"


def _reachable() -> bool:
    try:
        d = graph.make_driver()
        ok = graph.verify_connection(d)
        d.close()
        return ok
    except Exception:
        return False


@unittest.skipUnless(_reachable(), "no Neo4j reachable")
class TestGraphIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.driver = graph.make_driver()

    @classmethod
    def tearDownClass(cls):
        cls._wipe(cls.driver)
        cls.driver.close()

    @staticmethod
    def _wipe(driver):
        with driver.session() as s:
            s.run("MATCH (n {project_id:$pid}) DETACH DELETE n", pid=PID)

    def setUp(self):
        self._wipe(self.driver)

    def _seed_endpoint(self, baseurl, path, iface="llm-chat"):
        with self.driver.session() as s:
            s.run(
                """
                MERGE (b:BaseURL {url:$baseurl, user_id:$uid, project_id:$pid})
                MERGE (e:Endpoint {baseurl:$baseurl, path:$path, user_id:$uid, project_id:$pid})
                  SET e.method='POST', e.ai_interface_type=$iface, e.ai_model_family_guess='qwen'
                MERGE (b)-[:HAS_ENDPOINT]->(e)
                """,
                baseurl=baseurl, path=path, iface=iface, uid=UID, pid=PID,
            )

    def _count(self, cypher, **kw):
        with self.driver.session() as s:
            return s.run(cypher, **kw).single()[0]

    # --- target loader --- #
    def test_load_all_ai_reads_seeded(self):
        self._seed_endpoint("http://h:8000", "/v1/chat/completions")
        with self.driver.session() as s:
            targets = tl.load_targets(s, UID, PID)
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].ai_interface_type, "llm-chat")
        self.assertEqual(targets[0].path, "/v1/chat/completions")

    def test_load_all_ai_excludes_non_llm_sentinel(self):
        # recon stamps every crawled endpoint; only chat endpoints are attackable.
        self._seed_endpoint("http://h:8000", "/v1/chat/completions", iface="llm-chat")
        self._seed_endpoint("http://h:8000", "/about", iface="non-llm")
        self._seed_endpoint("http://h:8000", "/v1/embeddings", iface="llm-embedding")
        with self.driver.session() as s:
            targets = tl.load_targets(s, UID, PID)  # headless: no explicit selection
        paths = sorted(t.path for t in targets)
        self.assertEqual(paths, ["/v1/chat/completions"])  # non-llm + embedding excluded

    def test_load_selected_enriches_from_graph(self):
        self._seed_endpoint("http://h:8000", "/v1/chat/completions")
        with self.driver.session() as s:
            targets = tl.load_targets(
                s, UID, PID,
                selected=[{"baseurl": "http://h:8000", "path": "/v1/chat/completions"}])
        self.assertEqual(targets[0].ai_model_family_guess, "qwen")

    # --- normalizer linkage --- #
    def test_write_finding_links_to_endpoint(self):
        self._seed_endpoint("http://h:8000", "/v1/chat/completions")
        target = tl.Target(baseurl="http://h:8000", path="/v1/chat/completions",
                           ai_interface_type="llm-chat")
        f = make_dummy_finding(target, "skeleton", "itest")
        with self.driver.session() as s:
            linked = write_finding(s, f, UID, PID)
        self.assertTrue(linked)
        edges = self._count(
            "MATCH (:Endpoint {project_id:$pid})-[r:HAS_VULNERABILITY]->(:Vulnerability) RETURN count(r)",
            pid=PID)
        self.assertEqual(edges, 1)

    def test_write_finding_is_idempotent(self):
        self._seed_endpoint("http://h:8000", "/v1/chat/completions")
        target = tl.Target(baseurl="http://h:8000", path="/v1/chat/completions")
        f = make_dummy_finding(target, "skeleton", "itest")
        with self.driver.session() as s:
            write_finding(s, f, UID, PID)
            write_finding(s, f, UID, PID)  # same deterministic id -> MERGE
        vulns = self._count("MATCH (v:Vulnerability {project_id:$pid}) RETURN count(v)", pid=PID)
        self.assertEqual(vulns, 1)

    def test_fallback_to_baseurl_when_no_endpoint(self):
        # Seed only a BaseURL (no Endpoint on the attacked path).
        with self.driver.session() as s:
            s.run("MERGE (b:BaseURL {url:$u, user_id:$uid, project_id:$pid})",
                  u="http://h:8000", uid=UID, pid=PID)
        f = Finding(source="skeleton", chip="prompt-injection", name="n",
                    baseurl="http://h:8000", path="/missing", ai_owasp_llm_id="LLM01",
                    ai_payload_class="x")
        with self.driver.session() as s:
            linked = write_finding(s, f, UID, PID)
        self.assertFalse(linked)  # not linked to an Endpoint
        edges = self._count(
            "MATCH (:BaseURL {project_id:$pid})-[r:HAS_VULNERABILITY]->(:Vulnerability) RETURN count(r)",
            pid=PID)
        self.assertEqual(edges, 1)  # fell back to BaseURL


if __name__ == "__main__":
    unittest.main(verbosity=2)
