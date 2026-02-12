"""
Mock OAuth 2.0 Token Exchange Server (RFC 8693)

A lightweight FastAPI server that simulates an IDP token exchange endpoint.
Used for testing LiteLLM's OBO (On-Behalf-Of) token exchange flow with MCP servers.

Usage:
    pip install fastapi uvicorn
    python server.py

The server listens on port 9999 and provides:
    POST /oauth2/token  - Token exchange endpoint (RFC 8693)
    GET  /health        - Health check
"""

import hashlib
import json
import time
from datetime import datetime

import uvicorn
from fastapi import FastAPI, Form, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="Mock Token Exchange Server (RFC 8693)")

TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
DEFAULT_EXPIRES_IN = 3600

# In-memory log of exchanges for debugging
exchange_log: list = []


@app.post("/oauth2/token")
async def token_exchange(
    request: Request,
    grant_type: str = Form(...),
    subject_token: str = Form(...),
    subject_token_type: str = Form("urn:ietf:params:oauth:token-type:access_token"),
    audience: str = Form(None),
    scope: str = Form(None),
    client_id: str = Form(None),
    client_secret: str = Form(None),
):
    """RFC 8693 Token Exchange endpoint.

    Validates the request parameters, logs them, and returns a mock exchanged token.
    The exchanged token encodes the audience and a hash of the subject_token so you
    can verify which user token was exchanged and for which target.
    """
    timestamp = datetime.utcnow().isoformat()

    # Log the exchange request
    log_entry = {
        "timestamp": timestamp,
        "grant_type": grant_type,
        "subject_token_preview": subject_token[:50] + "..." if len(subject_token) > 50 else subject_token,
        "subject_token_type": subject_token_type,
        "audience": audience,
        "scope": scope,
        "client_id": client_id,
        "client_secret_present": bool(client_secret),
    }
    exchange_log.append(log_entry)
    print(f"\n{'='*60}")
    print(f"TOKEN EXCHANGE REQUEST at {timestamp}")
    print(f"{'='*60}")
    print(json.dumps(log_entry, indent=2))

    # Validate grant_type
    if grant_type != TOKEN_EXCHANGE_GRANT_TYPE:
        print(f"ERROR: Invalid grant_type: {grant_type}")
        return JSONResponse(
            status_code=400,
            content={
                "error": "unsupported_grant_type",
                "error_description": f"Expected {TOKEN_EXCHANGE_GRANT_TYPE}, got {grant_type}",
            },
        )

    # Validate client credentials
    if not client_id or not client_secret:
        print("ERROR: Missing client credentials")
        return JSONResponse(
            status_code=401,
            content={
                "error": "invalid_client",
                "error_description": "client_id and client_secret are required",
            },
        )

    # Generate a deterministic exchanged token so it's debuggable
    token_hash = hashlib.sha256(
        f"{subject_token}:{audience}:{scope}".encode()
    ).hexdigest()[:16]
    exchanged_token = f"exchanged-{token_hash}-for-{audience or 'no-audience'}"

    response = {
        "access_token": exchanged_token,
        "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "token_type": "Bearer",
        "expires_in": DEFAULT_EXPIRES_IN,
        "scope": scope,
    }

    print(f"\nRESPONSE:")
    print(f"  access_token: {exchanged_token}")
    print(f"  expires_in: {DEFAULT_EXPIRES_IN}")
    print(f"{'='*60}\n")

    return response


@app.get("/health")
async def health():
    return {"status": "ok", "exchanges_processed": len(exchange_log)}


@app.get("/log")
async def get_log():
    """View all token exchange requests (for debugging)."""
    return {"exchanges": exchange_log}


@app.delete("/log")
async def clear_log():
    """Clear the exchange log."""
    exchange_log.clear()
    return {"status": "cleared"}


if __name__ == "__main__":
    print("Starting Mock Token Exchange Server on port 9999")
    print("Endpoints:")
    print("  POST http://localhost:9999/oauth2/token  - Token exchange")
    print("  GET  http://localhost:9999/health         - Health check")
    print("  GET  http://localhost:9999/log            - View exchange log")
    print()
    uvicorn.run(app, host="0.0.0.0", port=9999)
