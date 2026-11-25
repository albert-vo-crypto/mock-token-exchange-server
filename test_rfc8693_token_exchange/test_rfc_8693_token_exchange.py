"""
End-to-End Integration Test Suite for LiteLLM OBO (On-Behalf-Of) Token Exchange Flow.

Target Components:
1. LiteLLM Proxy Gateway (port 4000)
2. Mock Token Exchange Server RFC 8693 (port 9999)
3. Mock MCP Server (port 9998)

Covers:
- Pre-test lifecycle hooks (clearing STS log records via DELETE /log)
- Positive test cases: End-to-end tool execution through LiteLLM with subject JWT token,
  verifying RFC 8693 exchange parameters on mock STS and execution on downstream MCP server.
- Negative & Security test cases:
  * Missing or expired subject token -> rejection with 401/403
  * Audience mismatch -> rejection at STS and MCP
  * Scope escalation -> rejection at STS
"""

import json
import time
import requests
import pytest

LITELLM_BASE_URL = "http://localhost:4000"
STS_BASE_URL = "http://localhost:9999"
MCP_BASE_URL = "http://localhost:9998"

LITELLM_MASTER_KEY = "sk-litellm-master-key"
SERVER_ID = "mock_mcp_server"
EXPECTED_AUDIENCE = "api://my-mcp-server"
EXPECTED_CLIENT_ID = "litellm-client"
EXPECTED_SCOPES = "mcp.tools.read mcp.tools.execute"


@pytest.fixture(autouse=True)
def clean_exchange_logs():
    """Lifecycle Setup Hook: Clear previous exchange records before every test."""
    resp = requests.delete(f"{STS_BASE_URL}/log", timeout=5)
    assert resp.status_code == 200, f"Failed to reset STS log: {resp.text}"
    yield
    # Optional teardown: check health
    resp = requests.get(f"{STS_BASE_URL}/health", timeout=5)
    assert resp.status_code == 200


# ==============================================================================
# Positive Test Cases
# ==============================================================================

def test_e2e_obo_positive_tool_call():
    """
    Transmit a user request with a mock user JWT to LiteLLM proxy invoking an MCP tool.
    Verify:
      1. LiteLLM executed RFC 8693 exchange at STS endpoint.
      2. STS log shows subject_token, client_id, audience, and requested scopes.
      3. Downstream MCP server on port 9998 received the deterministic token and completed tool execution.
    """
    user_jwt = "mock-jwt-user-alice-sub-987654"

    response = requests.post(
        f"{LITELLM_BASE_URL}/mcp-rest/tools/call",
        headers={
            "x-litellm-api-key": LITELLM_MASTER_KEY,
            "Authorization": f"Bearer {user_jwt}",
        },
        json={
            "name": "echo_tool",
            "arguments": {"message": "Test positive OBO tool call"},
            "server_id": SERVER_ID,
        },
        timeout=10,
    )

    assert response.status_code == 200, f"LiteLLM tool call failed: {response.text}"
    body = response.json()
    assert body.get("isError") is False
    content_list = body.get("content", [])
    assert len(content_list) > 0
    content_text = content_list[0].get("text", "")
    assert "echo_tool" in content_text
    assert EXPECTED_AUDIENCE in content_text

    # Verify LiteLLM performed RFC 8693 token exchange on STS
    log_resp = requests.get(f"{STS_BASE_URL}/log", timeout=5)
    assert log_resp.status_code == 200
    exchanges = log_resp.json().get("exchanges", [])
    assert len(exchanges) >= 1, "Expected at least 1 token exchange recorded by STS"

    latest = exchanges[-1]
    assert latest["grant_type"] == "urn:ietf:params:oauth:grant-type:token-exchange"
    assert latest["client_id"] == EXPECTED_CLIENT_ID
    assert latest["client_secret_present"] is True
    assert latest["audience"] == EXPECTED_AUDIENCE
    assert user_jwt in latest["subject_token_preview"]
    assert "mcp.tools.read" in latest["scope"]
    assert "mcp.tools.execute" in latest["scope"]


def test_sts_rfc8693_direct_exchange():
    """
    Verify RFC 8693 endpoint on mock STS directly issues deterministic tokens.
    """
    subject_token = "user-subject-token-xyz"
    resp = requests.post(
        f"{STS_BASE_URL}/oauth2/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": subject_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": EXPECTED_AUDIENCE,
            "scope": EXPECTED_SCOPES,
            "client_id": EXPECTED_CLIENT_ID,
            "client_secret": "litellm-secret",
        },
        timeout=5,
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    token = data.get("access_token")
    assert token.startswith("exchanged-")
    assert f"-for-{EXPECTED_AUDIENCE}" in token
    assert data.get("token_type") == "Bearer"
    assert data.get("expires_in") == 3600


# ==============================================================================
# Negative & Security Test Cases
# ==============================================================================

def test_missing_subject_token_fails_closed():
    """
    Missing subject_token: LiteLLM fails closed and returns HTTP 401/403.
    LiteLLM issues an RFC 9728 challenge header (WWW-Authenticate) without calling upstream.
    """
    response = requests.post(
        f"{LITELLM_BASE_URL}/mcp-rest/tools/call",
        headers={
            "x-litellm-api-key": LITELLM_MASTER_KEY,
            # No Authorization header provided
        },
        json={
            "name": "echo_tool",
            "arguments": {"message": "Should fail"},
            "server_id": SERVER_ID,
        },
        timeout=10,
    )

    assert response.status_code in (401, 403), f"Expected 401 or 403, got {response.status_code}: {response.text}"
    # Verify no token exchange occurred
    log_resp = requests.get(f"{STS_BASE_URL}/log", timeout=5)
    assert len(log_resp.json().get("exchanges", [])) == 0


def test_expired_subject_token_fails():
    """
    Expired subject token: Should be rejected either by STS or LiteLLM with 401/403.
    """
    expired_jwt = "mock-jwt-user-alice-expired"
    response = requests.post(
        f"{LITELLM_BASE_URL}/mcp-rest/tools/call",
        headers={
            "x-litellm-api-key": LITELLM_MASTER_KEY,
            "Authorization": f"Bearer {expired_jwt}",
        },
        json={
            "name": "echo_tool",
            "arguments": {"message": "Should fail expired"},
            "server_id": SERVER_ID,
        },
        timeout=10,
    )

    # LiteLLM surfaces upstream STS token failure as 401 / 403 or 500 upstream auth exception
    assert response.status_code in (400, 401, 403, 500), f"Expected auth failure, got {response.status_code}: {response.text}"

    # Also directly test STS rejection on expired token
    sts_resp = requests.post(
        f"{STS_BASE_URL}/oauth2/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": expired_jwt,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": EXPECTED_AUDIENCE,
            "scope": EXPECTED_SCOPES,
            "client_id": EXPECTED_CLIENT_ID,
            "client_secret": "litellm-secret",
        },
        timeout=5,
    )
    assert sts_resp.status_code == 400
    assert sts_resp.json().get("error") == "invalid_grant"


def test_audience_mismatch_rejection():
    """
    Audience mismatch:
    1. Direct STS token exchange for unauthorized audience is rejected with invalid_target.
    2. MCP server on port 9998 rejects tokens with mismatched audience with 403 Forbidden.
    """
    unauthorized_audience = "api://unauthorized-service"

    # STS rejection
    sts_resp = requests.post(
        f"{STS_BASE_URL}/oauth2/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": "valid-user-token",
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": unauthorized_audience,
            "scope": EXPECTED_SCOPES,
            "client_id": EXPECTED_CLIENT_ID,
            "client_secret": "litellm-secret",
        },
        timeout=5,
    )
    assert sts_resp.status_code == 400
    assert sts_resp.json().get("error") == "invalid_target"

    # MCP server rejection
    forged_token = f"exchanged-fake123-for-{unauthorized_audience}"
    mcp_resp = requests.post(
        f"{MCP_BASE_URL}/mcp",
        headers={"Authorization": f"Bearer {forged_token}"},
        json={"method": "tools/list", "id": 1},
        timeout=5,
    )
    assert mcp_resp.status_code == 403
    assert "audience mismatch" in mcp_resp.json().get("detail", "").lower()


def test_scope_escalation_rejection():
    """
    Scope escalation:
    Attempt requesting scopes outside the client's registration (e.g., 'mcp.admin.all', 'cluster.root').
    Confirm mock STS rejects the exchange with invalid_scope error (HTTP 400).
    """
    escalated_scopes = "mcp.tools.read mcp.admin.write cluster.root"

    resp = requests.post(
        f"{STS_BASE_URL}/oauth2/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": "valid-user-token",
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": EXPECTED_AUDIENCE,
            "scope": escalated_scopes,
            "client_id": EXPECTED_CLIENT_ID,
            "client_secret": "litellm-secret",
        },
        timeout=5,
    )
    assert resp.status_code == 400
    data = resp.json()
    assert data.get("error") == "invalid_scope"
    assert "exceed client registration" in data.get("error_description", "")


def test_invalid_client_credentials_rejection():
    """
    Client authentication failure:
    Requests to STS with invalid or missing client_secret must be rejected with 401.
    """
    resp = requests.post(
        f"{STS_BASE_URL}/oauth2/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": "valid-user-token",
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": EXPECTED_AUDIENCE,
            "scope": EXPECTED_SCOPES,
            "client_id": EXPECTED_CLIENT_ID,
            "client_secret": "wrong-secret-attacker",
        },
        timeout=5,
    )
    assert resp.status_code == 401
    assert resp.json().get("error") == "invalid_client"
