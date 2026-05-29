import hashlib
import os
import sys
import unittest
from unittest.mock import MagicMock


_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

from graph_db.mixins.recon.js_recon_mixin import JsReconMixin


class FakeSession:
    def __init__(self, endpoint_created=True, endpoint_linked=True):
        self.calls = []
        self.endpoint_created = endpoint_created
        self.endpoint_linked = endpoint_linked

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def run(self, query, **kwargs):
        self.calls.append((query, kwargs))
        if "RETURN created AS created" in query:
            return FakeResult({"created": self.endpoint_created})
        if "RETURN count(r) AS linked" in query:
            return FakeResult({"linked": 1 if self.endpoint_linked else 0})
        return FakeResult({"enriched": 0})


class FakeResult:
    def __init__(self, record):
        self.record = record

    def single(self):
        return self.record


class FakeDriver:
    def __init__(self, endpoint_created=True, endpoint_linked=True):
        self.session_obj = FakeSession(
            endpoint_created=endpoint_created,
            endpoint_linked=endpoint_linked,
        )

    def session(self):
        return self.session_obj


class GraphClient(JsReconMixin):
    def __init__(self, endpoint_created=True, endpoint_linked=True):
        self.driver = FakeDriver(
            endpoint_created=endpoint_created,
            endpoint_linked=endpoint_linked,
        )


class TestJsReconGraphIngestion(unittest.TestCase):
    def test_only_hittable_endpoints_are_ingested_with_validation_metadata_and_id(self):
        client = GraphClient()
        recon_data = {
            "domain": "example.com",
            "js_recon": {
                "scan_metadata": {"scan_timestamp": "2026-05-28T00:00:00Z"},
                "endpoints": [
                    {
                        "path": "/api/live",
                        "method": "POST",
                        "source_js": "https://example.com/app.js",
                        "base_url": "https://example.com",
                        "full_url": "https://example.com/api/live",
                        "validation_status": "hittable",
                        "status_code": 200,
                        "resolved_url": "https://example.com/api/live",
                    },
                    {
                        "path": "/api/dead",
                        "method": "GET",
                        "source_js": "https://example.com/app.js",
                        "base_url": "https://example.com",
                        "validation_status": "not_hittable",
                    },
                    {
                        "path": "/api/unknown",
                        "method": "GET",
                        "source_js": "https://example.com/app.js",
                        "base_url": "https://example.com",
                    },
                ],
            },
        }

        stats = client.update_graph_from_js_recon(recon_data, "u1", "p1")

        endpoint_calls = [
            kwargs for query, kwargs in client.driver.session_obj.calls
            if "MERGE (e:Endpoint" in query
        ]
        self.assertEqual(stats["endpoints_created"], 1)
        self.assertEqual(len(endpoint_calls), 1)

        expected_hash = hashlib.sha256(
            "https://example.com:POST:/api/live".encode()
        ).hexdigest()[:16]
        self.assertEqual(endpoint_calls[0]["id"], f"endpoint-u1-p1-js-{expected_hash}")
        self.assertEqual(endpoint_calls[0]["validation_status"], "hittable")
        self.assertEqual(endpoint_calls[0]["status_code"], 200)
        self.assertEqual(endpoint_calls[0]["resolved_url"], "https://example.com/api/live")
        link_calls = [
            (query, kwargs) for query, kwargs in client.driver.session_obj.calls
            if "MERGE (file)-[r:HAS_ENDPOINT]->(n)" in query
        ]
        self.assertEqual(len(link_calls), 1)
        self.assertIn("MATCH (n:Endpoint {path: $path, method: $method, baseurl: $baseurl", link_calls[0][0])
        self.assertNotIn("MATCH (n:Endpoint {id: $nid})", link_calls[0][0])
        self.assertEqual(link_calls[0][1]["path"], "/api/live")
        self.assertEqual(link_calls[0][1]["method"], "POST")
        self.assertEqual(link_calls[0][1]["baseurl"], "https://example.com")
        self.assertEqual(stats["errors"], [])

    def test_existing_endpoint_and_unmatched_file_link_do_not_increment_counts(self):
        client = GraphClient(endpoint_created=False, endpoint_linked=False)
        recon_data = {
            "domain": "example.com",
            "js_recon": {
                "scan_metadata": {"scan_timestamp": "2026-05-28T00:00:00Z"},
                "endpoints": [
                    {
                        "path": "/api/live",
                        "method": "POST",
                        "source_js": "https://example.com/app.js",
                        "base_url": "https://example.com",
                        "full_url": "https://example.com/api/live",
                        "validation_status": "hittable",
                        "status_code": 200,
                        "resolved_url": "https://example.com/api/live",
                    },
                ],
            },
        }

        stats = client.update_graph_from_js_recon(recon_data, "u1", "p1")

        self.assertEqual(stats["endpoints_created"], 0)
        self.assertEqual(stats["relationships_created"], 1)
        link_calls = [
            (query, kwargs) for query, kwargs in client.driver.session_obj.calls
            if "MERGE (file)-[r:HAS_ENDPOINT]->(n)" in query
        ]
        self.assertEqual(len(link_calls), 1)
        self.assertEqual(stats["errors"], [])


if __name__ == "__main__":
    unittest.main()
