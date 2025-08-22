from icebreaker.engine.orchestrator import Orchestrator

def test_orchestrator_has_methods():
    for m in ("discover","analyse","write_outputs"):
        assert hasattr(Orchestrator, m)
