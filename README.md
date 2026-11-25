# Mock Token Exchange Server (RFC 8693)

A lightweight FastAPI server that simulates an OAuth 2.0 Token Exchange (RFC 8693) endpoint. Used for testing LiteLLM's OBO (On-Behalf-Of) token exchange flow with MCP servers.

## Quick Start

```bash
pip install -r requirements.txt
python server.py
```

Server starts on `http://localhost:9999`.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/oauth2/token` | RFC 8693 Token Exchange endpoint |
| GET | `/health` | Health check |
| GET | `/log` | View all exchange requests |
| DELETE | `/log` | Clear exchange log |

## Token Exchange Request

```bash
curl -X POST http://localhost:9999/oauth2/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=<USER_JWT>" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "audience=api://my-mcp-server" \
  -d "scope=mcp.tools.read mcp.tools.execute" \
  -d "client_id=litellm-client" \
  -d "client_secret=litellm-secret"
```

## Response

```json
{
  "access_token": "exchanged-<hash>-for-api://my-mcp-server",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "mcp.tools.read mcp.tools.execute"
}
```

The exchanged token is deterministic (based on a hash of the input parameters), making it easy to verify in downstream services which user token was exchanged and for which audience.

## Usage with LiteLLM

Configure your LiteLLM proxy YAML:

```yaml
mcp_servers:
  my_mcp_server:
    url: http://localhost:9998/mcp
    transport: http
    auth_type: oauth2_token_exchange
    token_exchange_endpoint: http://localhost:9999/oauth2/token
    audience: api://my-mcp-server
    scopes:
      - mcp.tools.read
      - mcp.tools.execute
    client_id: litellm-client
    client_secret: litellm-secret
```

## Automated Testing & QA Test Suite

An end-to-end integration and security test suite is provided in `test_rfc8693_token_exchange/test_rfc_8693_token_exchange.py` to validate LiteLLM's RFC 8693 OBO flow alongside this mock STS server and downstream mock MCP server.

### Test Coverage:
1. **Lifecycle isolation**: `clean_exchange_logs` fixture calls `DELETE /log` before every test.
2. **Positive E2E Tool Execution**: User request with mock JWT through LiteLLM proxy -> STS RFC 8693 exchange -> Downstream MCP tool call execution on port 9998.
3. **Direct STS Verification**: Validates RFC 8693 conformance and deterministic token minting.
4. **Security & Negative Vectors**:
   - Missing subject token (LiteLLM fails closed with 401/403 and issues RFC 9728 challenge header).
   - Expired subject token rejection.
   - Audience mismatch rejection at STS and downstream MCP server.
   - Scope escalation rejection at STS (`invalid_scope`).
   - Invalid client credentials rejection (`invalid_client`).

### Running the Tests:

1. Install requirements:
   ```bash
   pip install -r requirements.txt
   ```
2. Start the local environment services (Mock STS on `:9999`, Mock MCP on `:9998`, LiteLLM on `:4000`).
3. Run the pytest suite:
   ```bash
   pytest -v test_rfc8693_token_exchange/test_rfc_8693_token_exchange.py
   ```
