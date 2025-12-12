import pytest
from icebreaker.core.models import RunContext, Service, Finding
from icebreaker.analyzers.http_basic import HTTPBasic
from icebreaker.analyzers.security_headers import SecurityHeaders


@pytest.fixture
def run_context():
    """Create a test run context."""
    return RunContext.new(preset="test", settings={})


@pytest.mark.asyncio
async def test_http_basic_server_header(run_context):
    """Test HTTPBasic analyzer detects server header."""
    analyzer = HTTPBasic()
    service = Service(
        target="example.com",
        port=80,
        name="http",
        meta={"server": "Apache/2.4.41"}
    )

    findings = await analyzer.run(run_context, service)

    # Should find server header exposure
    assert len(findings) > 0
    assert any("server" in f.title.lower() for f in findings)


@pytest.mark.asyncio
async def test_http_basic_no_tls_redirect(run_context):
    """Test HTTPBasic detects missing HTTPS redirect."""
    analyzer = HTTPBasic()
    service = Service(
        target="example.com",
        port=80,
        name="http",
        meta={"status": 200, "location": ""}
    )

    findings = await analyzer.run(run_context, service)

    # Should find missing TLS redirect
    assert any("https" in f.title.lower() for f in findings)


@pytest.mark.asyncio
async def test_http_basic_missing_hsts(run_context):
    """Test HTTPBasic detects missing HSTS."""
    analyzer = HTTPBasic()
    service = Service(
        target="example.com",
        port=443,
        name="https",
        meta={"hsts": ""}
    )

    findings = await analyzer.run(run_context, service)

    # Should find missing HSTS
    assert any("hsts" in f.title.lower() for f in findings)


@pytest.mark.asyncio
async def test_security_headers_missing_csp(run_context):
    """Test SecurityHeaders detects missing CSP."""
    analyzer = SecurityHeaders()
    service = Service(
        target="example.com",
        port=443,
        name="https",
        meta={"content-security-policy": ""}
    )

    findings = await analyzer.run(run_context, service)

    # Should find missing CSP
    assert any("content-security-policy" in f.title.lower() for f in findings)


@pytest.mark.asyncio
async def test_security_headers_weak_csp(run_context):
    """Test SecurityHeaders detects weak CSP."""
    analyzer = SecurityHeaders()
    service = Service(
        target="example.com",
        port=443,
        name="https",
        meta={"content-security-policy": "default-src 'unsafe-inline'"}
    )

    findings = await analyzer.run(run_context, service)

    # Should find weak CSP
    assert any("weak" in f.title.lower() and "csp" in f.title.lower() for f in findings)


@pytest.mark.asyncio
async def test_security_headers_missing_x_frame(run_context):
    """Test SecurityHeaders detects missing X-Frame-Options."""
    analyzer = SecurityHeaders()
    service = Service(
        target="example.com",
        port=443,
        name="https",
        meta={"x-frame-options": ""}
    )

    findings = await analyzer.run(run_context, service)

    # Should find missing X-Frame-Options
    assert any("x-frame-options" in f.title.lower() for f in findings)
