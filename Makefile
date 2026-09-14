.PHONY: install test test-cov lint security build clean snap deb-src

install:
	pip install -e ".[full,dev,security]"

test:
	pytest --no-cov

test-cov:
	pytest --cov-fail-under=60
	@echo "HTML report: htmlcov/index.html"

lint:
	ruff check src tests scripts honeypot-auditor.py
	ruff format --check src tests scripts honeypot-auditor.py
	mypy src/honeypot_auditor

security:
	semgrep scan --config p/python --config p/security-audit --config p/secrets --error --metrics off .
	bandit -c pyproject.toml -r src scripts honeypot-auditor.py
	pip-audit
	detect-secrets scan > .detect-secrets.json
	python -c 'import json; data=json.load(open(".detect-secrets.json", encoding="utf-8")); assert not any(data["results"].values()), data["results"]'
	@rm -f .detect-secrets.json
	@gitleaks git --redact --verbose || { echo "Install gitleaks to run the history scan"; exit 1; }

build:
	python -m build

snap:
	snapcraft pack

deb-src:
	debuild -S -d

clean:
	rm -rf .pytest_cache .ruff_cache htmlcov coverage.xml .coverage .coverage.* dist build *.egg-info
	rm -rf parts prime stage *.snap
	rm -rf debian/.debhelper debian/honeypot-auditor debian/files debian/*.substvars debian/*.debhelper.log
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
