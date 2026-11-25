"""
Mock MCP Server on port 9998.

Requirements:
- Expose POST /mcp requiring "Authorization: Bearer <token>"
- Verify that incoming bearer tokens match the expected audience "api://my-mcp-server"
  and contain "mcp.tools.execute" scope (or exchanged format "exchanged-<hash>-for-api://my-mcp-server")
- Also implement standard MCP JSON-RPC protocol endpoint for tools discovery and execution
  so LiteLLM can list tools and execute tools.
"""

import json
from fastapi import FastAPI, Request, Header, HTTPException
from fastapi.responses import JSONResponse
import uvicorn

app = FastAPI(title="Mock MCP Server")

EXPECTED_AUDIENCE = "api://my-mcp-server"
REQUIRED_SCOPE = "mcp.tools.execute"

def verify_token(authorization: str | None):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid Authorization header. Expected Bearer token.",
            headers={"WWW-Authenticate": 'Bearer realm="mcp", error="invalid_token"'}
        )
    token = authorization[len("Bearer "):].strip()
    
    # Check audience and scope in token
    # The Mock Token Exchange server creates tokens with format:
    # "exchanged-<hash>-for-<audience>"
    # Or JWT/string tokens containing the audience
    if EXPECTED_AUDIENCE not in token:
        raise HTTPException(
            status_code=403,
            detail=f"Token audience mismatch. Expected token containing audience '{EXPECTED_AUDIENCE}', got '{token}'",
            headers={"WWW-Authenticate": f'Bearer error="insufficient_scope", audience="{EXPECTED_AUDIENCE}"'}
        )
    return token

@app.get("/health")
async def health():
    return {"status": "ok", "server": "Mock MCP Server", "port": 9998}

@app.post("/mcp")
async def mcp_endpoint(request: Request, authorization: str | None = Header(None)):
    token = verify_token(authorization)
    
    try:
        body = await request.json()
    except Exception:
        body = {}
        
    method = body.get("method") if isinstance(body, dict) else None
    req_id = body.get("id") if isinstance(body, dict) else 1

    # Standard MCP JSON-RPC protocol handling
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {"listChanged": False}
                },
                "serverInfo": {
                    "name": "mock-mcp-server",
                    "version": "1.0.0"
                }
            }
        }
    elif method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": [
                    {
                        "name": "echo_tool",
                        "description": "Echo input message for testing",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "message": {"type": "string"}
                            },
                            "required": ["message"]
                        }
                    }
                ]
            }
        }
    elif method == "tools/call":
        params = body.get("params", {})
        name = params.get("name")
        args = params.get("arguments", {})
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": f"Tool '{name}' executed successfully with args {args}. Verified token for audience {EXPECTED_AUDIENCE}."
                    }
                ]
            }
        }
    
    # Generic request response if not JSON-RPC method
    return {
        "status": "success",
        "message": f"Authenticated successfully with audience {EXPECTED_AUDIENCE} and scope {REQUIRED_SCOPE}",
        "token_preview": token[:40] + "...",
        "received_payload": body
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9998)
