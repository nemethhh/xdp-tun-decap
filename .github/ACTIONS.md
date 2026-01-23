# GitHub Actions & Local Testing Guide

This document explains the CI/CD setup and how to test GitHub Actions locally using [nektos/act](https://github.com/nektos/act).

## Available Workflows

### 1. CI Workflow (`.github/workflows/ci.yml`)

**Triggers:**
- Push to `master`, `main`, or `develop` branches
- Pull requests to these branches
- Manual workflow dispatch

**Jobs:**
- `build-and-test`: Builds the XDP program and runs unit tests
- `integration-test`: Runs Docker-based integration tests
- `lint-and-format`: Checks code formatting and common issues

**Artifacts:**
- BPF object file (`tun_decap.bpf.o`)
- BPF skeleton header (`tun_decap.skel.h`)
- Test binary (`test_decap`)
- Retained for 30 days

### 2. Release Workflow (`.github/workflows/release.yml`)

**Triggers:**
- Push of version tags (e.g., `v1.0.0`, `v2.1.3`)
- Manual workflow dispatch with tag input

**Artifacts:**
- Release tarball with source and binaries
- Individual build artifacts
- SHA256 checksums
- GitHub Release with changelog

## Creating a Release

### Automatic Release (Recommended)

```bash
# Make sure you're on the main branch with all changes committed
git checkout master
git pull origin master

# Create and push a version tag
VERSION="v1.0.0"  # Use semantic versioning
git tag -a $VERSION -m "Release $VERSION"
git push origin $VERSION

# GitHub Actions will automatically:
# 1. Build all artifacts
# 2. Generate changelog from commits
# 3. Create GitHub Release
# 4. Upload artifacts
```

### Manual Release

If you need to create a release manually:

1. Go to GitHub Actions in your repository
2. Select "Release" workflow
3. Click "Run workflow"
4. Enter the version tag (e.g., `v1.0.0`)
5. Click "Run workflow"

## Version Numbering

Use [Semantic Versioning](https://semver.org/) (MAJOR.MINOR.PATCH):

- **MAJOR**: Breaking changes (e.g., v2.0.0)
- **MINOR**: New features, backward compatible (e.g., v1.1.0)
- **PATCH**: Bug fixes, backward compatible (e.g., v1.0.1)

Examples:
- `v1.0.0` - Initial release
- `v1.1.0` - Added IPv6 support
- `v1.1.1` - Fixed whitelist lookup bug
- `v2.0.0` - Changed map structure (breaking)

## Local Testing with nektos/act

[nektos/act](https://github.com/nektos/act) allows you to run GitHub Actions locally using Docker.

### Installation

**macOS:**
```bash
brew install act
```

**Linux:**
```bash
# Download latest release
curl -s https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash

# Or use package manager (if available)
# Ubuntu/Debian: sudo apt install act
# Arch: sudo pacman -S act
```

**Docker:**
```bash
alias act='docker run --rm -it -v $(pwd):/workspace -w /workspace -v /var/run/docker.sock:/var/run/docker.sock nektos/act:latest'
```

### Configuration

The repository includes `.actrc` with default settings:
- Uses `ubuntu-22.04` images from `catthehacker`
- Mounts Docker socket for integration tests
- Sets fake tokens for local testing

### Running Workflows Locally

**List available workflows:**
```bash
act -l
```

**Run CI workflow:**
```bash
# Run all CI jobs
act push

# Run specific job
act push -j build-and-test

# Run with verbose output
act push -v
```

**Test release workflow:**
```bash
# Simulate tag push
act push -e .github/test-events/tag-push.json

# Or test manually
act workflow_dispatch -w .github/workflows/release.yml
```

**Dry run (see what would run):**
```bash
act push -n
```

### Creating Test Events

Create `.github/test-events/tag-push.json`:
```json
{
  "ref": "refs/tags/v1.0.0-test",
  "repository": {
    "name": "xdp-tun-decap",
    "owner": {
      "login": "your-username"
    }
  }
}
```

Then run:
```bash
act push -e .github/test-events/tag-push.json
```

### Limitations of Local Testing

**act** has some limitations compared to real GitHub Actions:

1. **No Kernel BTF**: Local containers don't have kernel BTF data
   - vmlinux.h generation will use placeholder
   - Some tests may be skipped

2. **No BPF Support**: Container kernels don't support BPF
   - Can test build process
   - Cannot run actual BPF programs

3. **Secrets**: Need to provide secrets manually
   - GitHub tokens won't work
   - Use `-s` flag: `act -s GITHUB_TOKEN=xxx`

4. **Artifacts**: Artifact upload/download is simulated
   - Files stored in `/tmp/act-artifacts`

5. **Integration Tests**: May need adjustments
   - Docker-in-Docker can be tricky
   - Use `--container-daemon-socket -` in .actrc

### Best Practices

**Use act for:**
- ✅ Testing workflow syntax
- ✅ Verifying job dependencies
- ✅ Checking build scripts
- ✅ Debugging workflow logic
- ✅ Testing before pushing

**Don't rely on act for:**
- ❌ BPF program verification
- ❌ Full integration tests
- ❌ Performance testing
- ❌ Kernel-specific features

**Recommended workflow:**
1. Write/modify GitHub Actions workflow
2. Test syntax with `act -n` (dry run)
3. Test build process with `act push -j build-and-test`
4. Push to GitHub for full testing
5. Review CI results
6. Merge when green

### Debugging

**View logs:**
```bash
act push -v  # Verbose
act push -vv # Very verbose (debug)
```

**Interactive shell in job:**
```bash
# Not directly supported, but can debug container
docker ps  # Find container ID while act is running
docker exec -it <container-id> /bin/bash
```

**Check artifacts:**
```bash
# Artifacts are stored in temp directory
ls -la /tmp/act-artifacts/
```

## Workflow Maintenance

### Updating Dependencies

Edit `.github/workflows/ci.yml` to update package versions:

```yaml
- name: Install dependencies
  run: |
    sudo apt-get update
    sudo apt-get install -y \
      clang \
      llvm \
      libelf-dev \
      # ... add new dependencies here
```

### Adding New Jobs

```yaml
new-job:
  runs-on: ubuntu-22.04
  needs: build-and-test  # Optional: wait for other job

  steps:
  - name: Checkout
    uses: actions/checkout@v4

  - name: Your step
    run: |
      echo "Do something"
```

### Caching Dependencies

To speed up builds, add caching:

```yaml
- name: Cache dependencies
  uses: actions/cache@v4
  with:
    path: |
      ~/.cache/clang
      /usr/include
    key: ${{ runner.os }}-deps-${{ hashFiles('Makefile') }}
```

## Troubleshooting

### Build fails in CI but works locally

**Check:**
- Kernel version differences
- Missing dependencies in workflow
- Environment variables
- File permissions

**Solution:**
- Run `act push` to test locally
- Compare `apt list --installed` between environments
- Check GitHub Actions logs carefully

### Release workflow doesn't trigger

**Check:**
- Tag format: must be `v*.*.*` (e.g., `v1.0.0`)
- Tag pushed to GitHub: `git push origin v1.0.0`
- Workflow file syntax: `yamllint .github/workflows/release.yml`

**Solution:**
```bash
# List tags
git tag -l

# Create and push tag
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0

# Delete tag if needed
git tag -d v1.0.0
git push origin :refs/tags/v1.0.0
```

### act fails with Docker errors

**Common issues:**
- Docker daemon not running
- Insufficient permissions
- Docker socket not mounted

**Solutions:**
```bash
# Check Docker is running
docker ps

# Run Docker commands without sudo
sudo usermod -aG docker $USER
newgrp docker

# Use correct socket mount
act push --container-daemon-socket /var/run/docker.sock
```

## Additional Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [nektos/act Repository](https://github.com/nektos/act)
- [act User Guide](https://nektosact.com/)
- [GitHub Actions Marketplace](https://github.com/marketplace?type=actions)
- [Workflow Syntax Reference](https://docs.github.com/en/actions/reference/workflow-syntax-for-github-actions)
