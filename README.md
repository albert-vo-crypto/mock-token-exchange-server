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
