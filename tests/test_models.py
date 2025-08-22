from icebreaker.core.models import Target, Service, Finding, RunContext

def test_target_model():
    t = Target(address="192.168.8.1")
    assert t.address == "192.168.8.1"
