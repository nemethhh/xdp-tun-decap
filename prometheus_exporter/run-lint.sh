#!/bin/bash
# Run linters via Docker Compose

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

usage() {
    cat << EOF
Usage: $0 [OPTIONS] [LINTER]

Run Python linters via Docker Compose

LINTERS:
  all        Run all linters (default)
  flake8     PEP 8 style checker
  pylint     Comprehensive static analysis
  black      Code formatting checker
  isort      Import statement ordering checker
  mypy       Static type checker
  format     Auto-format code (modifies files!)

OPTIONS:
  -h, --help     Show this help message
  -b, --build    Force rebuild Docker image
  -c, --clean    Clean up containers after run

EXAMPLES:
  $0                    # Run all linters
  $0 flake8             # Run only flake8
  $0 --build all        # Rebuild image and run all linters
  $0 format             # Auto-format code

EOF
}

# Parse arguments
LINTER="all"
BUILD_FLAG=""
CLEAN_FLAG="--rm"

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            exit 0
            ;;
        -b|--build)
            BUILD_FLAG="--build"
            shift
            ;;
        -c|--clean)
            CLEAN_FLAG="--rm"
            shift
            ;;
        all|flake8|pylint|black|isort|mypy|format|lint)
            LINTER=$1
            shift
            ;;
        *)
            echo -e "${RED}Error: Unknown option $1${NC}"
            usage
            exit 1
            ;;
    esac
done

# Map 'all' to 'lint' service
if [ "$LINTER" = "all" ]; then
    LINTER="lint"
fi

echo -e "${YELLOW}=== XDP Exporter Linter Tests ===${NC}"
echo "Linter: $LINTER"
echo "Working directory: $SCRIPT_DIR"
echo

# Run Docker Compose
if docker compose -f docker-compose.lint.yml run $BUILD_FLAG $CLEAN_FLAG "$LINTER"; then
    echo
    echo -e "${GREEN}✓ Linter tests passed!${NC}"
    exit 0
else
    echo
    echo -e "${RED}✗ Linter tests failed${NC}"
    exit 1
fi
