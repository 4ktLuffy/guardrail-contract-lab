PY := .venv/bin/python
GCL := .venv/bin/gcl

.PHONY: setup test demo lint clean

setup:
	uv venv --python 3.13 .venv
	uv pip install --python $(PY) -e '.[dev]'

test:
	$(PY) -m pytest -q

demo:
	$(GCL) demo --out demo-out

lint:
	.venv/bin/ruff check gcl tests

clean:
	rm -rf demo-out .pytest_cache .ruff_cache
