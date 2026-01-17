# Makefile for XDP Tunnel Decapsulation Prometheus Exporter

.PHONY: help install test lint format clean docker-lint docker-build

# Default target
help:
	@echo "XDP Tunnel Decapsulation Prometheus Exporter - Make targets:"
	@echo ""
	@echo "  install        Install Python dependencies"
	@echo "  test           Run exporter test script"
	@echo "  lint           Run all linters via Docker"
	@echo "  lint-flake8    Run flake8 only"
	@echo "  lint-pylint    Run pylint only"
	@echo "  lint-black     Check code formatting with black"
	@echo "  lint-isort     Check import ordering with isort"
	@echo "  lint-mypy      Run type checker"
	@echo "  format         Auto-format code (modifies files!)"
	@echo "  docker-build   Build Docker linting image"
	@echo "  clean          Clean up Docker containers and cache"
	@echo ""

# Install dependencies
install:
	pip3 install -r requirements.txt

# Run test script (requires root and XDP program loaded)
test:
	@echo "Running exporter test (requires root)..."
	sudo ./test_exporter.sh

# Docker-based linting (recommended)
lint:
	@echo "Running all linters via Docker..."
	./run-lint.sh all

lint-flake8:
	@echo "Running flake8..."
	./run-lint.sh flake8

lint-pylint:
	@echo "Running pylint..."
	./run-lint.sh pylint

lint-black:
	@echo "Checking code formatting..."
	./run-lint.sh black

lint-isort:
	@echo "Checking import ordering..."
	./run-lint.sh isort

lint-mypy:
	@echo "Running type checker..."
	./run-lint.sh mypy

# Auto-format code
format:
	@echo "WARNING: This will modify xdp_tun_decap_exporter.py"
	@read -p "Continue? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		./run-lint.sh format; \
	fi

# Docker operations
docker-build:
	@echo "Building Docker linting image..."
	docker compose -f docker-compose.lint.yml build

docker-clean:
	@echo "Cleaning up Docker containers..."
	docker compose -f docker-compose.lint.yml down -v --remove-orphans

# Clean up
clean: docker-clean
	@echo "Cleaning Python cache..."
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	@echo "✓ Cleaned"

# CI target (for continuous integration)
ci: lint
	@echo "✓ CI checks passed"
