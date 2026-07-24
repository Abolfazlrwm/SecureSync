.PHONY: help install lint format format-check typecheck test test-cov \
        benchmark clean docker-build docker-up docs pre-commit

help:
	@echo "SecureSync — developer commands"
	@echo "  make install       Install package + dev dependencies"
	@echo "  make lint          Run ruff"
	@echo "  make format        Run black (rewrites files)"
	@echo "  make format-check  Run black --check (CI mode)"
	@echo "  make typecheck     Run mypy --strict"
	@echo "  make test          Run pytest"
	@echo "  make test-cov      Run pytest with coverage report"
	@echo "  make benchmark     Run the benchmark suite (benchmarks/)"
	@echo "  make pre-commit    Run all pre-commit hooks against all files"
	@echo "  make docker-build  Build the SecureSync Docker image"
	@echo "  make docker-up     Start SecureSync via docker-compose"
	@echo "  make clean         Remove caches, build artifacts"

install:
	pip install -e ".[dev]"
	pre-commit install

lint:
	ruff check src tests

format:
	black src tests

format-check:
	black --check src tests

typecheck:
	mypy src

test:
	@pytest; code=$$?; \
	if [ $$code -eq 5 ]; then \
		echo "No tests collected yet (expected pre-Phase 1) — not a failure."; \
		exit 0; \
	fi; \
	exit $$code

test-cov:
	@pytest --cov-report=html; code=$$?; \
	if [ $$code -eq 5 ]; then \
		echo "No tests collected yet (expected pre-Phase 1) — not a failure."; \
		exit 0; \
	fi; \
	exit $$code

benchmark:
	python -m benchmarks

pre-commit:
	pre-commit run --all-files

docker-build:
	docker build -t securesync:dev .

docker-up:
	docker compose up --build

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage dist build *.egg-info
