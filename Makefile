# Kyber-PQC Build Automation
PYTHON := python3
PIP := pip3

.PHONY: all install build test lint clean test-c test-go

all: install test

install:
	$(PIP) install -U pip wheel
	$(PIP) install -e ".[dev]"

build:
	$(PYTHON) -m build --wheel

test: test-python test-c test-go

test-python:
	$(PYTHON) -m pytest src/tests/ --cov=kyber_pqc --cov-report=term-missing

test-c:
	$(MAKE) -C c test

test-go:
	$(MAKE) -C c lib
	cd go && CGO_ENABLED=1 go test ./...

lint:
	$(PYTHON) -m flake8 src/
	$(PYTHON) -m mypy src/kyber_pqc/

clean:
	rm -rf build/ dist/ *.egg-info/ .coverage .pytest_cache/ htmlcov/
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	$(MAKE) -C c clean
