# Agent-Warden Makefile
# Developer workflow automation

.PHONY: help install install-dev test test-cov lint format clean build publish

# Default target
help:
	@echo "Agent-Warden Development Commands"
	@echo "================================="
	@echo ""
	@echo "Setup:"
	@echo "  make install      Install package dependencies"
	@echo "  make install-dev  Install with dev dependencies"
	@echo ""
	@echo "Development:"
	@echo "  make test         Run tests"
	@echo "  make test-cov     Run tests with coverage"
	@echo "  make lint         Run linter (ruff)"
	@echo "  make format       Format code (ruff)"
	@echo "  make check        Run lint + test"
	@echo ""
	@echo "Build:"
	@echo "  make build        Build package"
	@echo "  make publish      Publish to PyPI"
	@echo "  make clean        Clean build artifacts"

# =============================================================================
# SETUP
# =============================================================================

install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"

# =============================================================================
# DEVELOPMENT
# =============================================================================

test:
	pytest tests/ -v

test-cov:
	pytest tests/ -v --cov=warden --cov-report=term-missing --cov-report=html

test-fast:
	pytest tests/ -v -x --tb=short

lint:
	ruff check warden/ tests/

lint-fix:
	ruff check warden/ tests/ --fix

format:
	ruff format warden/ tests/

format-check:
	ruff format warden/ tests/ --check

typecheck:
	mypy warden/ --ignore-missing-imports

check: lint test
	@echo "All checks passed!"

# =============================================================================
# BUILD & PUBLISH
# =============================================================================

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .ruff_cache/
	rm -rf .mypy_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

build: clean
	python -m build

publish: build
	twine upload dist/*

publish-test: build
	twine upload --repository testpypi dist/*

# =============================================================================
# EXAMPLES
# =============================================================================

example-basic:
	PYTHONPATH=. python examples/01_basic_usage.py

example-strands:
	PYTHONPATH=. python examples/02_strands_integration.py

example-audit:
	PYTHONPATH=. python examples/03_audit_logging.py

example-prod:
	PYTHONPATH=. python examples/04_production_setup.py
