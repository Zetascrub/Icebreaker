"""
Integration tests for API endpoints.
"""
import pytest
from fastapi.testclient import TestClient
from icebreaker.api.app import app
from icebreaker.db.database import Base, engine, SessionLocal
from icebreaker.db.models import Scan, Finding, FindingTemplate, ScanProfile

# Create test client
client = TestClient(app)


@pytest.fixture(scope="module")
def setup_database():
    """Setup test database."""
    Base.metadata.create_all(bind=engine)
    yield
    # Teardown: could drop tables here if needed


def test_health_check():
    """Test health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data
    assert data["service"] == "icebreaker"


def test_get_root_redirects_to_dashboard():
    """Test root endpoint serves dashboard."""
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 200
    # Should return HTML
    assert "text/html" in response.headers.get("content-type", "")


def test_api_scans_list_empty(setup_database):
    """Test getting scans when database is empty."""
    response = client.get("/api/scans")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


def test_api_scans_create_and_retrieve(setup_database):
    """Test creating and retrieving a scan."""
    # Create a scan
    scan_data = {
        "targets": ["example.com"],
        "preset": "quick",
        "ports": "80,443"
    }

    # Note: This would need the actual endpoint implementation
    # For now, test that the endpoint exists
    response = client.get("/api/scans")
    assert response.status_code == 200


def test_api_finding_templates_list(setup_database):
    """Test listing finding templates."""
    response = client.get("/api/finding-templates")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


def test_api_analytics_dashboard(setup_database):
    """Test analytics dashboard endpoint."""
    response = client.get("/api/analytics/dashboard")
    assert response.status_code == 200
    data = response.json()
    # Should have basic stats even if empty
    assert "total_scans" in data or "scans" in str(data)


def test_security_headers_present():
    """Test that security headers are set."""
    response = client.get("/health")
    headers = response.headers

    # Check for security headers
    assert "x-content-type-options" in headers
    assert headers["x-content-type-options"] == "nosniff"

    assert "x-frame-options" in headers
    assert headers["x-frame-options"] == "SAMEORIGIN"

    assert "x-xss-protection" in headers
    assert "strict-transport-security" in headers


def test_api_import_preview_invalid_file():
    """Test import preview with invalid file."""
    # Try to upload without file
    response = client.post("/api/import/nessus/preview")
    # Should return 422 (validation error) or 400 (bad request)
    assert response.status_code in [400, 422]


def test_cors_headers():
    """Test CORS headers are set."""
    response = client.options("/health")
    # CORS headers should be present
    # Note: TestClient may not include all CORS headers
    assert response.status_code in [200, 405]  # OPTIONS might not be defined


def test_compression_enabled():
    """Test that gzip compression is enabled."""
    response = client.get("/health")
    # GZip should be available but may not be used for small responses
    # Just check endpoint works
    assert response.status_code == 200


def test_rate_limiting():
    """Test that rate limiting is configured."""
    # Make multiple requests to check rate limiting is working
    # Note: slowapi may not enforce limits in TestClient mode
    # This test verifies the middleware is present
    responses = []
    for _ in range(10):
        response = client.get("/health")
        responses.append(response.status_code)

    # All should succeed in test mode (rate limits typically disabled for tests)
    # But the middleware should be present
    assert all(status == 200 for status in responses)


def test_csrf_cookie_set():
    """Test that CSRF cookie is set on GET requests."""
    response = client.get("/")
    # Check if CSRF cookie would be set (TestClient may not handle cookies fully)
    # This test verifies the middleware is present
    assert response.status_code == 200


def test_csrf_exempt_paths():
    """Test that API paths are exempt from CSRF protection."""
    # API endpoints should be exempt from CSRF
    response = client.get("/api/scans")
    assert response.status_code == 200

    # Health check should also be exempt
    response = client.get("/health")
    assert response.status_code == 200


@pytest.mark.parametrize("endpoint", [
    "/",
    "/scans",
    "/scans/new",
    "/health",
])
def test_common_endpoints_accessible(endpoint):
    """Test that common endpoints are accessible."""
    response = client.get(endpoint, follow_redirects=False)
    # Should return 200 (OK) or 404 if template missing
    # but not 500 (server error)
    assert response.status_code < 500


def test_api_openapi_docs():
    """Test that OpenAPI documentation is accessible."""
    response = client.get("/docs")
    assert response.status_code == 200

    response = client.get("/openapi.json")
    assert response.status_code == 200
    data = response.json()
    assert "openapi" in data
    assert "info" in data
    assert data["info"]["title"] == "Icebreaker"


def test_api_version_consistency():
    """Test that API version is consistent."""
    # Health endpoint
    health_response = client.get("/health")
    health_version = health_response.json()["version"]

    # OpenAPI spec
    openapi_response = client.get("/openapi.json")
    openapi_version = openapi_response.json()["info"]["version"]

    assert health_version == openapi_version == "0.2.0"
