# Default venv path – adjust if yours differs
VENV = ~/.venvs/icebreaker

.PHONY: install test lint run clean

install:
	. $(VENV)/bin/activate && pip install -e .

test:
	. $(VENV)/bin/activate && pytest -q

lint:
	. $(VENV)/bin/activate && ruff check icebreaker tests

run:
	. $(VENV)/bin/activate && icebreaker -q -t scope.txt --preset quick --out-dir /tmp/ib-latest || test $$? -eq 2

clean:
	rm -rf .pytest_cache __pycache__ */__pycache__ *.egg-info dist build
