from icebreaker.analyzers.http_basic import HTTPBasic
from icebreaker.core.models import RunContext, Service
from datetime import datetime, timezone
import tempfile, os
import pytest

def ctx(tmp):
    return RunContext(
        run_id="test",
        preset="quick",
        out_dir=tmp,
        started_at=datetime.now(timezone.utc),
        settings={},
    )

def test_http_flags_redirect_and_hsts(tmp_path):
    c = ctx(tmp_path.as_posix())
    http = Service(target="t", port=80, name="http", meta={"status": 200})
    https = Service(target="t", port=443, name="https", meta={"hsts": ""})

    hb = HTTPBasic()
    f1 = [*__import__('asyncio').get_event_loop().run_until_complete(hb.run(c, http))]
    f2 = [*__import__('asyncio').get_event_loop().run_until_complete(hb.run(c, https))]

    assert any("no_tls_redirect" in x.id and x.severity == "MEDIUM" for x in f1)
    assert any("missing_hsts" in x.id and x.severity == "LOW" for x in f2)

@pytest.mark.asyncio
async def test_http_flags_redirect_and_hsts(tmp_path):
    c = ctx(tmp_path.as_posix())
    http = Service(target="t", port=80, name="http", meta={"status": 200})
    https = Service(target="t", port=443, name="https", meta={"hsts": ""})

    hb = HTTPBasic()
    f1 = await hb.run(c, http)
    f2 = await hb.run(c, https)

    assert any("no_tls_redirect" in x.id and x.severity == "MEDIUM" for x in f1)
    assert any("missing_hsts" in x.id and x.severity == "LOW" for x in f2)