# ---------------------------------------------------------------------------
# Makefile for the SCA Tool Evaluation Framework (Poetry-based)
#
# Common targets:
#   make install      Install dependencies via Poetry
#   make test         Run the pytest suite
#   make coverage     Run tests with coverage report (XML + terminal)
#   make lint         Run ruff linter
#   make format       Auto-format with ruff
#   make sbom         Generate a CycloneDX SBOM from poetry.lock
#   make sonar        Run SonarQube scanner (requires SONAR_URL, SONAR_TOKEN)
#   make clean        Remove build artifacts
#   make help         Show this help
# ---------------------------------------------------------------------------

SHELL        := /bin/bash

BUILD_DIR    := build
SBOM_DIR     := $(BUILD_DIR)/sbom
COVERAGE_DIR := $(BUILD_DIR)/coverage
SBOM_JSON    := $(SBOM_DIR)/sbom.json
SBOM_XML     := $(SBOM_DIR)/sbom.xml
SONAR_PROP   := sonar-project.properties

POETRY        ?= poetry
CYCLO         ?= cyclonedx-py
PYTEST        ?= pytest
RUFF          ?= ruff
COVERAGE      ?= coverage
# Add path to local sonar scanner
SONAR_SCANNER ?= sonar-scanner


.PHONY: help install test coverage lint format sbom sonar clean check-tools check-sonarqube all

.DEFAULT_GOAL := help

help:
	@awk 'BEGIN {FS = ":.*##"; printf "Targets:\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# ---------------------------------------------------------------------------
# Environment setup
# ---------------------------------------------------------------------------
install: ## Install project dependencies via Poetry
	@$(POETRY) install

check-tools:
	@$(POETRY) --version >/dev/null 2>&1 || { echo "Missing: poetry"; exit 1; }
	@$(POETRY) run $(PYTEST) --version >/dev/null 2>&1 || { \
	  echo "Missing: pytest (install with 'poetry add --group dev pytest pytest-cov')"; exit 1; }

check-sonarqube:
	@test -f $(SONAR_PROP) || { echo "Missing: $(SONAR_PROP)"; exit 1; }
	@command -v $(SONAR_SCANNER) >/dev/null 2>&1 || { \
	  echo "ERROR: '$(SONAR_SCANNER)' not found on PATH."; \
	  echo "       Install via: brew install sonar-scanner   (macOS)"; \
	  echo "       or download:  https://docs.sonarsource.com/sonarqube-server/latest/analyzing-source-code/scanners/sonarscanner/"; \
	  echo "       See section 11 of .env_example for details."; \
	  exit 1; \
	}

# ---------------------------------------------------------------------------
# Testing
# ---------------------------------------------------------------------------
test: ## Run pytest
	@$(POETRY) run $(PYTEST)

$(COVERAGE_DIR):
	@mkdir -p $@

coverage: $(COVERAGE_DIR) ## Run tests with coverage
	@echo "[INFO] Running tests with coverage report"
	@$(POETRY) run $(PYTEST) \
	  --cov=src \
	  --cov-report=term-missing \
	  --cov-report=xml:$(COVERAGE_DIR)/coverage.xml

# ---------------------------------------------------------------------------
# Linting / formatting
# ---------------------------------------------------------------------------
lint: ## Run ruff linter
	@$(POETRY) run $(RUFF) check .

format: ## Auto-format with ruff
	@$(POETRY) run $(RUFF) format .

# ---------------------------------------------------------------------------
# SBOM
# ---------------------------------------------------------------------------
$(SBOM_DIR):
	@mkdir -p $@

sbom: $(SBOM_DIR) ## Generate CycloneDX SBOM (JSON + XML) from poetry.lock
	@echo "[INFO] Generating CycloneDX SBOM from poetry.lock"
	@$(POETRY) run $(CYCLO) poetry -o $(SBOM_JSON)
	@$(POETRY) run $(CYCLO) poetry -o $(SBOM_XML)

# ---------------------------------------------------------------------------
# SonarQube (optional)
#
# Prerequisites:
#   1. sonar-scanner CLI installed (default path: /usr/local/sonarscanner/bin/sonar-scanner)
#        macOS:   brew install sonar-scanner
#        manual:  https://docs.sonarsource.com/sonarqube-server/latest/analyzing-source-code/scanners/sonarscanner/
#        Override the path with: SONAR_SCANNER=/path/to/sonar-scanner make sonar
#
#   2. sonar-project.properties present in the project root (already committed).
#      It sets sonar.projectKey, sonar.sources=src, sonar.tests=tests,
#      sonar.python.coverage.reportPaths=build/coverage/coverage.xml
#
#   3. A SonarQube server reachable at SONAR_URL (Community Edition or higher).
#      Create a User Token in the SonarQube UI:
#        My Account → Security → Generate Tokens → User Token → copy once
#
#   4. Coverage report must exist — run `make coverage` first.
#      The XML report (build/coverage/coverage.xml, Cobertura format) is read
#      by SonarQube to display line-level coverage. The pyproject.toml option
#      `relative_files = true` ensures file paths match the `sonar.sources=src`
#      layout so SonarQube maps them correctly.
#
#   5. SBOM (optional) — run `make sbom` first; if missing, scan continues
#      without SBOM dependency data.
#
# Typical invocation:
#   SONAR_URL=https://sonar.example.com \
#   SONAR_TOKEN=squ_xxxxxxxxxxxxxxxxxxxx \
#   make coverage sbom sonar
# ---------------------------------------------------------------------------
sonar: check-sonarqube ## Run SonarQube scanner (requires SONAR_URL, SONAR_TOKEN)
	@if [ -z "$(SONAR_URL)" ] || [ -z "$(SONAR_TOKEN)" ]; then \
	  echo "ERROR: SONAR_URL and/or SONAR_TOKEN are not set."; \
	  echo "       See section 11 of .env_example for setup instructions."; \
	  echo "       Typical invocation:"; \
	  echo "         SONAR_URL=https://sonar.example.com \\"; \
	  echo "         SONAR_TOKEN=squ_xxxxxxxxxxxx \\"; \
	  echo "         make sonar"; \
	  exit 1; \
	fi
	@if [ ! -f "$(COVERAGE_DIR)/coverage.xml" ]; then \
	  echo "ERROR: coverage report '$(COVERAGE_DIR)/coverage.xml' not found."; \
	  echo "       Generate it first with:  make coverage"; \
	  exit 1; \
	fi
	@if [ ! -f "$(SBOM_JSON)" ]; then \
	  echo "WARN:  SBOM '$(SBOM_JSON)' not found — scan will run without SBOM."; \
	  echo "       Generate with:  make sbom   (recommended before 'make sonar')"; \
	fi
	@echo "[INFO] Running SonarQube scanner against $(SONAR_URL)"
	@$(SONAR_SCANNER) \
	  -Dsonar.host.url=$(SONAR_URL) \
	  -Dsonar.token=$(SONAR_TOKEN) \
	  -Dsonar.projectBaseDir=. \
	  -Dsonar.sbom.jsonReportPath=$(SBOM_JSON) \
	  -Dsonar.python.coverage.reportPaths=$(COVERAGE_DIR)/coverage.xml

# ---------------------------------------------------------------------------
# Housekeeping
# ---------------------------------------------------------------------------
all: sbom coverage ## Build everything

clean: ## Remove build artifacts
	@rm -rf $(BUILD_DIR) .pytest_cache .ruff_cache .coverage coverage.xml
