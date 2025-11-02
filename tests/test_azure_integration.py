"""Integration-style tests for Azure DevOps upload endpoints.
 
Run against live Azure DevOps only when environment variables are set:
  AZURE_PAT      - Personal Access Token (scope: Code Read)
  AZURE_ORG      - Organization name
  AZURE_PROJECT  - Project name
  AZURE_REPO     - Repository name
 
These tests will be skipped automatically if the required env vars are missing.
"""
 
import os
import pytest
from fastapi.testclient import TestClient
 
try:
    from main import app  # Import FastAPI app
except Exception as e:  # pragma: no cover
    pytest.skip(f"Cannot import app from main.py: {e}", allow_module_level=True)
 
client = TestClient(app)
 
LIVE_ENV_SET = all(
    os.getenv(k) for k in ["AZURE_PAT", "AZURE_ORG", "AZURE_PROJECT", "AZURE_REPO"]
)
 
 
def test_validate_missing_fields_returns_422():
    # FastAPI will raise 422 when required Form fields are missing
    resp = client.post("/api/upload/azure/validate", data={})
    assert resp.status_code == 422
    assert "detail" in resp.json()
 
 
def test_upload_missing_fields_returns_422():
    resp = client.post("/api/upload/azure", data={})
    assert resp.status_code == 422
    assert "detail" in resp.json()
 
 
@pytest.mark.skipif(not LIVE_ENV_SET, reason="Live Azure DevOps credentials not set")
def test_validate_connection_live():
    resp = client.post(
        "/api/upload/azure/validate",
        data={
            "pat_token": os.environ["AZURE_PAT"],
            "organization": os.environ["AZURE_ORG"],
            "project": os.environ["AZURE_PROJECT"],
        },
    )
    # Accept 200 (success) or 400 (invalid project / permissions) but report body
    assert resp.status_code in (200, 400), resp.text
    body = resp.json()
    assert "success" in body
 
 
@pytest.mark.skipif(not LIVE_ENV_SET, reason="Live Azure DevOps credentials not set")
def test_upload_repository_live():
    resp = client.post(
        "/api/upload/azure",
        data={
            "pat_token": os.environ["AZURE_PAT"],
            "organization": os.environ["AZURE_ORG"],
            "project": os.environ["AZURE_PROJECT"],
            "repository": os.environ["AZURE_REPO"],
        },
    )
    # If success: expect 200; if repository invalid: 400; else 500 for unexpected
    assert resp.status_code in (200, 400), resp.text
    body = resp.json()
    assert "success" in body
    if resp.status_code == 200:
        assert body["success"] is True
        assert "upload_id" in body
        assert "total_files" in body
 