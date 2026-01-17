# Linting and Code Quality

This directory includes Docker-based linting infrastructure to ensure code quality and consistency.

## Quick Start

Run all linters:
```bash
make lint
# or
./run-lint.sh
```

## Available Linters

### 1. flake8 (PEP 8 Style Checker)
Checks code style compliance with PEP 8 guidelines.

```bash
make lint-flake8
# or
./run-lint.sh flake8
```

### 2. pylint (Comprehensive Static Analysis)
Performs detailed static analysis including code smells, bugs, and style issues.

```bash
make lint-pylint
# or
./run-lint.sh pylint
```

### 3. black (Code Formatter)
Checks if code follows black's formatting style.

```bash
make lint-black
# or
./run-lint.sh black
```

### 4. isort (Import Sorter)
Checks if imports are properly sorted and organized.

```bash
make lint-isort
# or
./run-lint.sh isort
```

### 5. mypy (Type Checker)
Performs static type checking.

```bash
make lint-mypy
# or
./run-lint.sh mypy
```

## Auto-Formatting

To automatically format code (modifies files):
```bash
make format
# or
./run-lint.sh format
```

**Warning:** This will modify `xdp_tun_decap_exporter.py` in place!

## Docker Compose

The linting infrastructure uses Docker Compose for reproducible, isolated testing.

### Architecture

```
Dockerfile.lint           # Linting image with all tools
docker-compose.lint.yml   # Service definitions for each linter
run-lint.sh               # Wrapper script for easy usage
```

### Services

```bash
# Run specific service directly
docker compose -f docker-compose.lint.yml run --rm flake8
docker compose -f docker-compose.lint.yml run --rm pylint
docker compose -f docker-compose.lint.yml run --rm black
```

### Building

Force rebuild of Docker image:
```bash
make docker-build
# or
./run-lint.sh --build all
```

## Configuration

### Line Length
- Max line length: **100 characters**
- Configured in all linters for consistency

### Pylint Disabled Checks
The following checks are disabled for practical reasons:
- `C0103`: Invalid name (allows short variable names)
- `R0913`: Too many arguments
- `R0914`: Too many local variables
- `R0915`: Too many statements
- `W0703`: Catching too general exception
- `E0401`: Import error (prometheus_client not in container)
- `W0201`: Attribute defined outside __init__ (ctypes structures)
- `R0903`: Too few public methods (data structures)

### Black & isort
- Compatible profiles (black-compatible isort)
- Line length: 100 characters
- Consistent import ordering

## Integration

### Pre-commit Hook
Add to `.git/hooks/pre-commit`:
```bash
#!/bin/bash
cd prometheus_exporter
./run-lint.sh all || exit 1
```

Make executable:
```bash
chmod +x .git/hooks/pre-commit
```

### CI/CD
GitHub Actions example:
```yaml
- name: Lint Python code
  run: |
    cd prometheus_exporter
    make lint
```

GitLab CI example:
```yaml
lint:
  script:
    - cd prometheus_exporter
    - make lint
```

## Troubleshooting

### Docker not found
Install Docker and Docker Compose:
```bash
# Ubuntu/Debian
sudo apt-get install docker.io docker-compose

# Or use Docker Desktop
```

### Permission denied
Make script executable:
```bash
chmod +x run-lint.sh
```

### Container build fails
Clean and rebuild:
```bash
make clean
make docker-build
```

### Linter fails but code looks correct
Check specific linter output:
```bash
./run-lint.sh flake8  # More detailed output
```

## Development Workflow

1. **Write code**: Edit `xdp_tun_decap_exporter.py`
2. **Check style**: `make lint-flake8`
3. **Check quality**: `make lint-pylint`
4. **Auto-format**: `make format` (optional)
5. **Run all checks**: `make lint`
6. **Test functionality**: `make test` (requires root)

## Current Code Quality

All linters pass with the current code:

```
✓ flake8  - PEP 8 compliant
✓ pylint  - Score: 9.5+/10
✓ black   - Properly formatted
✓ isort   - Imports sorted
✓ mypy    - Type hints valid
```

## Resources

- [PEP 8](https://peps.python.org/pep-0008/) - Python Style Guide
- [flake8](https://flake8.pycqa.org/) - Style enforcement
- [pylint](https://pylint.org/) - Code analysis
- [black](https://black.readthedocs.io/) - Code formatter
- [isort](https://pycqa.github.io/isort/) - Import sorter
- [mypy](https://mypy.readthedocs.io/) - Type checker
