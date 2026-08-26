.PHONY: install test test-cov lint build clean

install:
	pip install -e ".[full,dev]"

test:
	pytest --no-cov

test-cov:
	pytest --cov-fail-under=60
	@echo "HTML report: htmlcov/index.html"

lint:
	ruff check src tests

build:
	python -m build

clean:
	rm -rf .pytest_cache .ruff_cache htmlcov coverage.xml .coverage .coverage.* dist build *.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
