#!/usr/bin/env bash
# =============================================================================
# Aggregator for the Kali MCP auth + loopback + DB-secret hardening tests
# (STRIDE S10 / E1 / I9 / S13). Runs every tier in order and exits non-zero on
# the first failure. Suites that need a running stack skip themselves cleanly.
#
#   bash tests/run_security_remediation_suite.sh
# =============================================================================
set -uo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

FAILED=0
run() {
    echo
    echo "############################################################"
    echo "# $1"
    echo "############################################################"
    shift
    if "$@"; then echo ">> OK"; else echo ">> FAILED"; FAILED=1; fi
}

# Unit / integration (no running stack required)
run "Unit: redamon.sh secret generation"        bash tests/redamon_secrets_test.sh
run "Integration: host-port publish policy"      bash tests/test_port_bindings.sh
run "Unit: MCP bearer middleware (ASGI)"         python3 mcp/servers/tests/test_auth_middleware.py
run "Unit: agent MCP client auth wiring"         python3 agentic/tests/test_system_mcp_auth.py
run "Integration: SSE auth round-trip (real MCP)" python3 mcp/servers/tests/test_sse_auth_integration.py

# Security (skips if stack down)
run "Security: reported exploit is blocked"      bash tests/test_exploit_blocked.sh

echo
echo "============================================================"
if [[ $FAILED -eq 0 ]]; then
    echo "ALL SECURITY-REMEDIATION SUITES GREEN"
else
    echo "SECURITY-REMEDIATION SUITES: FAILURES ABOVE"
fi
exit $FAILED
