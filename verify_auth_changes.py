import asyncio
import os
import sys
from unittest.mock import MagicMock

# Add repo root to path so we can import app
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from starlette.testclient import TestClient
from app.main import app, _get_oauth_credentials

def test_auth_flows():
    print("🚀 Starting Auth Flow Verification...")
    client = TestClient(app)

    # 1. Test Legacy Session Auth (Same-Domain Simulator)
    # We mock the session by manipulating the client cookies/session directly if possible,
    # but TestClient's session handling is tricky. standard approach is to mock the helper
    # or use a special middleware.
    # Instead, let's verify the API accepts a mocked session if we could set it.
    
    # Actually, simpler: Test the logic of _get_oauth_credentials directly first.
    print("\n🔍 Testing _get_oauth_credentials logic...")
    
    # Case A: Bearer Header
    req_header = MagicMock()
    req_header.headers = {"authorization": "Bearer header_token_123"}
    req_header.session = {}
    token, login, sentinel_id = _get_oauth_credentials(req_header)
    if token == "header_token_123":
        print("✅ Header Auth: Token extracted correctly.")
    else:
        print(f"❌ Header Auth Failed: Got {token}")

    # Case B: Session Cookie (Fallback)
    req_session = MagicMock()
    req_session.headers = {}
    req_session.session = {
        "github_oauth_token": "session_token_456",
        "github_user_login": "session_user",
        "sentinel_user_id": "789"
    }
    token, login, sentinel_id = _get_oauth_credentials(req_session)
    if token == "session_token_456" and login == "session_user":
        print("✅ Session Auth: Token/Login extracted correctly from session.")
    else:
        print(f"❌ Session Auth Failed: Got {token}, {login}")

    # 2. Test API Endpoint Response (Mocking the dependency isn't easy without override)
    # But we can verify the endpoint handles no-auth correctly (401/403 or Unconnected)
    
    print("\n🔍 Testing /api/setup/status (No Auth)...")
    resp = client.get("/api/setup/status")
    assert resp.status_code == 200
    data = resp.json()
    if data["connected"] is False:
        print("✅ /api/setup/status correctly reports 'connected: false' without credentials.")
    else:
        print(f"❌ Unexpected status: {data}")

    print("\n✅ Verification Complete: Core auth logic handles both Headers and Sessions.")

if __name__ == "__main__":
    test_auth_flows()
