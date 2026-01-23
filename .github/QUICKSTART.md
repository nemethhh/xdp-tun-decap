# Quick Start: GitHub Actions & Releases

## 📋 TL;DR

```bash
# Test workflows locally
act push                                    # Run CI
act -l                                      # List workflows
act push -j build-and-test                 # Run specific job

# Create a release
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0                     # Triggers automatic release
```

## 🚀 First Time Setup

### Install act (Local Testing)

```bash
# macOS
brew install act

# Linux
curl -s https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash

# Or use Docker
alias act='docker run --rm -it -v $(pwd):/workspace -w /workspace -v /var/run/docker.sock:/var/run/docker.sock nektos/act:latest'
```

### Pull Required Docker Images

```bash
# Pull act runner image (only needed once)
docker pull catthehacker/ubuntu:act-22.04
```

## 🔄 CI Workflow

**Automatically runs on:**
- Push to `master`, `main`, or `develop`
- Pull requests to these branches

**What it does:**
1. Installs dependencies (clang, libbpf, bpftool, etc.)
2. Builds BPF program
3. Runs unit tests
4. Runs integration tests (Docker)
5. Checks code formatting

**Test locally:**
```bash
act push                     # Run all CI jobs
act push -j build-and-test  # Run specific job
act push -n                  # Dry run (show what would run)
act push -v                  # Verbose output
```

## 📦 Release Workflow

### Creating Releases

**Method 1: Push a tag (Recommended)**
```bash
# Make sure everything is committed
git status

# Create version tag (semantic versioning)
git tag -a v1.0.0 -m "Release v1.0.0: Initial release"

# Push tag to GitHub
git push origin v1.0.0

# GitHub Actions automatically:
# - Builds artifacts
# - Generates changelog
# - Creates GitHub Release
```

**Method 2: Manual trigger**
```bash
# Go to: https://github.com/YOUR_ORG/xdp-tun-decap/actions
# Click: "Release" workflow → "Run workflow"
# Enter: v1.0.0
# Click: "Run workflow"
```

**Test release locally:**
```bash
# Simulate tag push
act push -e .github/test-events/tag-push.json -w .github/workflows/release.yml

# Or test specific job
act workflow_dispatch -w .github/workflows/release.yml -j create-release
```

### Version Numbering

Use [Semantic Versioning](https://semver.org/):

```
v<MAJOR>.<MINOR>.<PATCH>
```

Examples:
- `v1.0.0` - Initial release
- `v1.1.0` - New feature (backward compatible)
- `v1.1.1` - Bug fix
- `v2.0.0` - Breaking change

### What Gets Released

The release includes:
- ✅ `tun_decap.bpf.o` - BPF program object
- ✅ `tun_decap.skel.h` - BPF skeleton header
- ✅ `test_decap` - Test binary
- ✅ Source code tarball
- ✅ SHA256 checksums
- ✅ Auto-generated changelog
- ✅ Documentation (README.md, CLAUDE.md)

## 🐛 Troubleshooting

### CI fails but builds locally?

```bash
# Test with act to match CI environment
act push

# Check dependencies
act push -v | grep "apt-get install"

# Compare environment
act push -j build-and-test --list-actions
```

### Tag doesn't trigger release?

```bash
# Verify tag format (must be v*.*.*)
git tag -l 'v*'

# Check tag is pushed to GitHub
git ls-remote --tags origin

# Delete and recreate if needed
git tag -d v1.0.0
git push origin :refs/tags/v1.0.0
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0
```

### act fails with Docker errors?

```bash
# Check Docker is running
docker ps

# Fix permissions (Linux)
sudo usermod -aG docker $USER
newgrp docker

# Try with explicit socket
act push --container-daemon-socket /var/run/docker.sock
```

## 📚 Common Commands

### act Commands

```bash
act -l                                    # List workflows and jobs
act push                                  # Run push event (CI)
act pull_request                          # Run PR event
act workflow_dispatch                     # Run manual workflow
act -j JOB_NAME                          # Run specific job
act -n                                    # Dry run
act -v                                    # Verbose
act -vv                                   # Very verbose (debug)
act --list-actions                        # List available actions
act -W .github/workflows/ci.yml          # Run specific workflow file
```

### Git Tag Commands

```bash
git tag                                   # List all tags
git tag -a v1.0.0 -m "message"           # Create annotated tag
git push origin v1.0.0                   # Push specific tag
git push origin --tags                   # Push all tags
git tag -d v1.0.0                        # Delete local tag
git push origin :refs/tags/v1.0.0       # Delete remote tag
git describe --tags                       # Show current tag
git show v1.0.0                          # Show tag details
```

### GitHub CLI (gh)

```bash
gh release list                           # List releases
gh release view v1.0.0                   # View release details
gh release download v1.0.0               # Download release
gh release create v1.0.0                 # Create release manually
gh workflow list                          # List workflows
gh workflow run release.yml              # Trigger workflow
gh run list                               # List workflow runs
gh run view                               # View latest run
```

## 🔗 Resources

- [Full Documentation](.github/ACTIONS.md) - Complete guide
- [GitHub Actions Docs](https://docs.github.com/en/actions)
- [nektos/act Repo](https://github.com/nektos/act)
- [Semantic Versioning](https://semver.org/)

## 💡 Tips

**Before Pushing:**
1. Test locally: `act push`
2. Check syntax: `act push -n`
3. Verify builds: `make clean && make all`
4. Run tests: `make test`

**Release Checklist:**
1. ✅ All tests passing
2. ✅ Documentation updated
3. ✅ CHANGELOG or commit messages clear
4. ✅ Version number decided (semver)
5. ✅ Tag created and pushed
6. ✅ Wait for Actions to complete
7. ✅ Verify release on GitHub

**Act Best Practices:**
- Use act for workflow syntax validation
- Don't rely on act for BPF-specific testing
- Always test on real GitHub Actions before releasing
- Keep .actrc configuration up to date

## ⚙️ Configuration Files

```
.github/
├── workflows/
│   ├── ci.yml              # CI build and test
│   └── release.yml         # Release creation
├── test-events/
│   └── tag-push.json       # Test event for act
├── ACTIONS.md              # Full documentation
└── QUICKSTART.md           # This file

.actrc                      # act configuration
.clang-format               # Code formatting rules
```

## 🆘 Getting Help

```bash
# GitHub Actions
gh help workflow

# act
act --help
act -l

# Makefile
make help
```

For issues: https://github.com/YOUR_ORG/xdp-tun-decap/issues
