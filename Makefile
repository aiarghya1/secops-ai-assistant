.PHONY: install dev test lint clean help

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install dependencies
	pip install -e ".[dev]"

dev: ## Start the development server
	python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

test: ## Run all tests
	python -m pytest tests/ -v --tb=short

test-cov: ## Run tests with coverage
	python -m pytest tests/ -v --cov=app --cov-report=html --cov-report=term

lint: ## Run linter
	python -m ruff check app/ tests/
	python -m ruff format --check app/ tests/

format: ## Auto-format code
	python -m ruff format app/ tests/
	python -m ruff check --fix app/ tests/

typecheck: ## Run type checker
	python -m mypy app/

clean: ## Clean build artifacts
	rm -rf build/ dist/ *.egg-info/ .pytest_cache/ .mypy_cache/ htmlcov/ .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

demo: ## Run in demo mode (no API keys needed)
	APP_DEBUG=true python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
