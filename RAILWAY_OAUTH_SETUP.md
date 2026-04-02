# Deploying a FastMCP Server to Railway with Claude Desktop OAuth

This guide explains how to add OAuth 2.0 protection to a FastMCP-based MCP server and deploy it to Railway so Claude Desktop can connect via "Add custom connector".

---

## How it works

Claude Desktop uses the OAuth 2.0 **authorization code + PKCE** flow to connect to remote MCP servers. When you add a custom connector it hits these endpoints in order:

1. `GET /.well-known/oauth-protected-resource` — discovers the authorization server
2. `GET /.well-known/oauth-authorization-server` — discovers `/authorize` and `/token`
3. `GET /authorize?response_type=code&client_id=...&code_challenge=...` — gets a code (server auto-approves)
4. `POST /token` with code + PKCE verifier — gets a Bearer token
5. `GET /sse` with `Authorization: Bearer <token>` — establishes the MCP connection

We implement this as a **pure ASGI wrapper** around FastMCP's `sse_app()`. This avoids Starlette's `BaseHTTPMiddleware` which buffers responses and breaks SSE streaming.

---

## Files to create / modify

### 1. `pyproject.toml` — add dependencies

```toml
dependencies = [
    "mcp>=1.0.0",
    "httpx>=0.27.0",
    "requests>=2.31.0",
    "pydantic>=2.0.0",
    "python-dotenv>=1.0.0",
    "uvicorn>=0.20.0",
]
```

### 2. `railway.json` — Railway deployment config

```json
{
  "$schema": "https://railway.app/railway.schema.json",
  "deploy": {
    "healthcheckPath": "/health",
    "startCommand": "uvicorn your_package.server:app --host=0.0.0.0 --port=$PORT"
  }
}
```

### 3. `Procfile` — required for Railway public routing

```
web: uvicorn your_package.server:app --host=0.0.0.0 --port=$PORT
```

> **Important:** The `web:` process type in the Procfile is what tells Railway to expose the service on the public internet. Without it, the container runs but external traffic is never routed to it.

### 4. `.env.example`

```
SERVICENOW_INSTANCE_URL=https://your-instance.service-now.com/
SERVICENOW_USERNAME=your-username
SERVICENOW_PASSWORD=your-password

# MCP Server OAuth (SSE transport only)
MCP_SERVER_CLIENT_ID=your-mcp-client-id
MCP_SERVER_CLIENT_SECRET=your-mcp-client-secret
MCP_SERVER_URL=https://your-railway-app.up.railway.app
```

---

## 5. `server.py` — the OAuth wrapper

Add these imports at the top:

```python
import base64
import hashlib
import hmac
import secrets
import time
import json
import inspect as _inspect
```

### Token helpers (module-level)

```python
def _make_signed_token(client_id: str, signing_key: bytes, ttl: int = 86400) -> str:
    expiry = int(time.time()) + ttl
    payload = f"{client_id}:{expiry}".encode()
    sig = hmac.new(signing_key, payload, hashlib.sha256).digest()
    payload_enc = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
    sig_enc = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{payload_enc}.{sig_enc}"


def _verify_signed_token(token: str, signing_key: bytes):
    try:
        payload_enc, sig_enc = token.rsplit(".", 1)
        payload = base64.urlsafe_b64decode(payload_enc + "==")
        sig = base64.urlsafe_b64decode(sig_enc + "==")
        expected = hmac.new(signing_key, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            return None
        client_id, expiry_str = payload.decode().rsplit(":", 1)
        if int(time.time()) > int(expiry_str):
            return None
        return client_id
    except Exception:
        return None
```

### OAuth ASGI wrapper (module-level)

```python
def create_oauth_protected_app(mcp_app, client_id: str, client_secret: str, server_url: str):
    from urllib.parse import parse_qs

    server_url = server_url.rstrip("/")
    signing_key = hashlib.sha256(f"mcp-token-signing:{client_secret}".encode()).digest()
    secret_digest = hashlib.sha256(client_secret.encode()).digest()
    _auth_codes: dict = {}

    async def _send_json(send, status: int, body: dict, extra_headers=None):
        data = json.dumps(body).encode()
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(data)).encode()),
            (b"access-control-allow-origin", b"*"),
        ]
        if extra_headers:
            headers.extend(extra_headers)
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": data, "more_body": False})

    async def _send_redirect(send, location: str):
        await send({"type": "http.response.start", "status": 302,
                    "headers": [(b"location", location.encode()), (b"content-length", b"0")]})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    async def _read_body(receive) -> bytes:
        body = b""
        while True:
            msg = await receive()
            body += msg.get("body", b"")
            if not msg.get("more_body", False):
                return body

    def _qs(scope) -> dict:
        qs = scope.get("query_string", b"").decode()
        return {k: v[0] for k, v in parse_qs(qs).items()} if qs else {}

    def _pkce_verify(code_verifier: str, code_challenge: str) -> bool:
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        return hmac.compare_digest(expected, code_challenge)

    async def protected_app(scope, receive, send):
        # Lifespan MUST be handled outside the HTTP try/except.
        # If a lifespan exception were caught by the HTTP error handler, it would
        # try to send an HTTP response on the lifespan channel, fail silently,
        # and return — making uvicorn think the server is shutting down.
        if scope["type"] == "lifespan":
            print("[MCP-Auth] lifespan delegating to mcp_app", flush=True)
            await mcp_app(scope, receive, send)
            return

        if scope["type"] != "http":
            await mcp_app(scope, receive, send)
            return

        path = scope.get("path", "")
        method = scope.get("method", "GET")
        print(f"[MCP-Auth] {method} {path}", flush=True)

        try:
            # OAuth discovery: resource metadata
            if path.startswith("/.well-known/oauth-protected-resource"):
                await _send_json(send, 200, {
                    "resource": server_url,
                    "authorization_servers": [server_url],
                })
                return

            # OAuth discovery: authorization server metadata
            if path == "/.well-known/oauth-authorization-server":
                await _send_json(send, 200, {
                    "issuer": server_url,
                    "authorization_endpoint": f"{server_url}/authorize",
                    "token_endpoint": f"{server_url}/token",
                    "grant_types_supported": ["authorization_code", "client_credentials"],
                    "response_types_supported": ["code"],
                    "code_challenge_methods_supported": ["S256"],
                    "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
                })
                return

            # Authorization endpoint — auto-approve, redirect with code
            if path == "/authorize" and method == "GET":
                params = _qs(scope)
                if params.get("response_type") != "code":
                    await _send_json(send, 400, {"error": "unsupported_response_type"})
                    return
                if not hmac.compare_digest(params.get("client_id", "").encode(), client_id.encode()):
                    await _send_json(send, 401, {"error": "invalid_client"})
                    return
                redirect_uri = params.get("redirect_uri", "")
                if not redirect_uri:
                    await _send_json(send, 400, {"error": "invalid_request"})
                    return

                code = secrets.token_urlsafe(32)
                _auth_codes[code] = {
                    "code_challenge": params.get("code_challenge", ""),
                    "redirect_uri": redirect_uri,
                    "expires_at": int(time.time()) + 300,
                }
                sep = "&" if "?" in redirect_uri else "?"
                location = f"{redirect_uri}{sep}code={code}"
                state = params.get("state", "")
                if state:
                    location += f"&state={state}"
                await _send_redirect(send, location)
                return

            # Token endpoint — exchange code or client_credentials
            if path in ("/token", "/oauth/token") and method == "POST":
                raw = await _read_body(receive)
                params = {k: v[0] for k, v in parse_qs(raw.decode()).items()}
                grant_type = params.get("grant_type", "")

                if grant_type == "authorization_code":
                    code = params.get("code", "")
                    entry = _auth_codes.pop(code, None)
                    if entry is None or int(time.time()) > entry["expires_at"]:
                        await _send_json(send, 400, {"error": "invalid_grant"})
                        return
                    if not hmac.compare_digest(params.get("client_id", "").encode(), client_id.encode()):
                        await _send_json(send, 401, {"error": "invalid_client"})
                        return
                    code_challenge = entry.get("code_challenge", "")
                    if code_challenge:
                        if not _pkce_verify(params.get("code_verifier", ""), code_challenge):
                            await _send_json(send, 400, {"error": "invalid_grant", "error_description": "PKCE failed"})
                            return
                    token = _make_signed_token(client_id, signing_key)
                    await _send_json(send, 200, {"access_token": token, "token_type": "bearer", "expires_in": 86400})
                    return

                if grant_type == "client_credentials":
                    id_ok = hmac.compare_digest(params.get("client_id", "").encode(), client_id.encode())
                    secret_ok = hmac.compare_digest(
                        hashlib.sha256(params.get("client_secret", "").encode()).digest(),
                        secret_digest,
                    )
                    if not (id_ok and secret_ok):
                        await _send_json(send, 401, {"error": "invalid_client"})
                        return
                    token = _make_signed_token(client_id, signing_key)
                    await _send_json(send, 200, {"access_token": token, "token_type": "bearer", "expires_in": 86400})
                    return

                await _send_json(send, 400, {"error": "unsupported_grant_type"})
                return

            # Health check
            if path == "/health":
                await _send_json(send, 200, {"status": "ok"})
                return

            # All other paths — require Bearer token
            headers_dict = dict(scope.get("headers", []))
            auth = headers_dict.get(b"authorization", b"").decode()
            if not auth.startswith("Bearer "):
                await _send_json(send, 401, {"error": "unauthorized"}, [
                    (b"www-authenticate",
                     f'Bearer realm="{server_url}", resource_metadata="{server_url}/.well-known/oauth-protected-resource"'.encode()),
                ])
                return
            if _verify_signed_token(auth[len("Bearer "):], signing_key) is None:
                await _send_json(send, 401, {"error": "invalid_token"}, [
                    (b"www-authenticate",
                     f'Bearer error="invalid_token", realm="{server_url}", resource_metadata="{server_url}/.well-known/oauth-protected-resource"'.encode()),
                ])
                return

            await mcp_app(scope, receive, send)

        except Exception as exc:
            print(f"[MCP-Auth] EXCEPTION: {exc}", flush=True)
            import traceback
            traceback.print_exc()
            try:
                await _send_json(send, 500, {"error": "internal_server_error", "detail": str(exc)})
            except Exception:
                pass

    return protected_app
```

### Disable FastMCP's DNS-rebinding protection

When creating your `FastMCP` instance, disable the transport security check. FastMCP rejects all external Host headers by default — since we handle auth at our layer, this is safe to disable:

```python
from mcp.server.fastmcp import FastMCP

try:
    from mcp.server.transport_security import TransportSecuritySettings
    _transport_security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
except Exception:
    _transport_security = None

_fastmcp_kwargs = {"dependencies": ["requests", "httpx", "pydantic"]}
if _transport_security is not None:
    _fastmcp_kwargs["transport_security"] = _transport_security

mcp = FastMCP("Your Server Name", **_fastmcp_kwargs)
```

### Module-level `app` variable (used by uvicorn)

At the bottom of `server.py`, create the `app` variable that uvicorn loads:

```python
import os
import inspect as _inspect

_SERVER_CLIENT_ID = os.environ.get("MCP_SERVER_CLIENT_ID")
_SERVER_CLIENT_SECRET = os.environ.get("MCP_SERVER_CLIENT_SECRET")
_SERVER_URL = os.environ.get("MCP_SERVER_URL", "")

# Resolve sse_app — it's a method in newer SDK versions
_sse = mcp.sse_app
if _inspect.ismethod(_sse):
    _sse = _sse()

if _SERVER_CLIENT_ID and _SERVER_CLIENT_SECRET:
    app = create_oauth_protected_app(_sse, _SERVER_CLIENT_ID, _SERVER_CLIENT_SECRET, _SERVER_URL)
    print("✅ MCP app initialized with OAuth protection", flush=True)
else:
    app = _sse
    print("⚠️  No OAuth credentials set — endpoint is public", flush=True)
```

---

## Railway setup

### Environment variables (set in Railway dashboard → Variables)

| Variable | Value |
|---|---|
| `MCP_SERVER_CLIENT_ID` | Any string you choose (e.g. `my_mcp_server`) |
| `MCP_SERVER_CLIENT_SECRET` | A strong random secret |
| `MCP_SERVER_URL` | Your Railway public URL **including `https://`** and no trailing slash, e.g. `https://my-app.up.railway.app`. Missing the scheme causes OAuth metadata to return URLs without `https://`, so re-auth silently fails and all requests return 401 after the token expires. |
| `SERVICENOW_INSTANCE_URL` | Your ServiceNow instance URL |
| `SERVICENOW_USERNAME` | ServiceNow username |
| `SERVICENOW_PASSWORD` | ServiceNow password |

### Railway networking

After deploying, go to **Railway dashboard → your service → Settings → Networking** and confirm the public domain is routing to the correct port. Check your startup logs for:

```
INFO:     Uvicorn running on http://0.0.0.0:XXXX
```

That `XXXX` must match the port configured in Railway's Networking settings. If not, update it there.

---

## Claude Desktop setup

In Claude Desktop → Settings → **Add custom connector**:

| Field | Value |
|---|---|
| Remote MCP server URL | `https://your-app.up.railway.app/sse` |
| OAuth Client ID | Value of `MCP_SERVER_CLIENT_ID` |
| OAuth Client Secret | Value of `MCP_SERVER_CLIENT_SECRET` |

---

## Common gotchas

| Problem | Cause | Fix |
|---|---|---|
| 502 "connection refused" | Railway domain routing to wrong port | Check Networking settings, match port to `$PORT` |
| 502 after health check passes | Lifespan scope caught by HTTP try/except | Handle `lifespan` scope BEFORE the try/except block |
| 421 Misdirected Request on `/sse` | FastMCP DNS-rebinding protection rejecting Host header | Disable via `TransportSecuritySettings(enable_dns_rebinding_protection=False)` |
| External requests fail, health check works | Procfile `web:` missing | Restore `web:` process type in Procfile |
| `sse_app` is not callable | It's a method, not a property in newer SDK | Call it: `mcp.sse_app()` (check with `inspect.ismethod`) |
| 401 after server restart / token expiry | `MCP_SERVER_URL` missing `https://` scheme | Set it to `https://your-app.up.railway.app` — without the scheme, metadata endpoints return schemeless URLs, re-auth silently fails, and expired tokens are never refreshed |
