# GitHub Actions Configuration

This directory contains GitHub Actions workflows and documentation for the XDP Tunnel Decapsulation project.

## 📁 Directory Structure

```
.github/
├── workflows/
│   ├── ci.yml              # Continuous Integration
│   └── release.yml         # Release automation
├── test-events/
│   └── tag-push.json       # Test event for local testing
├── ACTIONS.md              # Complete documentation
├── QUICKSTART.md           # Quick reference guide
└── README.md               # This file
```

## 🚀 Quick Links

- **[QUICKSTART.md](QUICKSTART.md)** - Start here! Common commands and quick reference
- **[ACTIONS.md](ACTIONS.md)** - Complete guide to workflows, act, and troubleshooting

## 📋 Workflows

### CI Workflow (`ci.yml`)

**Purpose:** Build and test on every push/PR

**Jobs:**
1. **build-and-test** - Compiles BPF program and runs unit tests
2. **integration-test** - Runs Docker-based integration tests
3. **lint-and-format** - Code style and quality checks

**Status:** ![CI](https://github.com/YOUR_ORG/xdp-tun-decap/workflows/CI/badge.svg)

### Release Workflow (`release.yml`)

**Purpose:** Create GitHub releases on version tags

**Triggers:** Push of `v*.*.*` tags (e.g., `v1.0.0`)

**Outputs:**
- GitHub Release with changelog
- Tarball with source and binaries
- Individual build artifacts
- SHA256 checksums

**Status:** ![Release](https://github.com/YOUR_ORG/xdp-tun-decap/workflows/Release/badge.svg)

## 🧪 Local Testing with act

Test workflows locally before pushing:

```bash
# Install act
brew install act  # macOS
# or
curl -s https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash

# Test CI
act push

# Test specific job
act push -j build-and-test

# Dry run
act push -n
```

Configuration is in [`.actrc`](../.actrc) at repository root.

See [QUICKSTART.md](QUICKSTART.md) for more commands.

## 🎯 Creating a Release

```bash
# 1. Ensure everything is committed and tested
git status
make test

# 2. Create and push version tag
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0

# 3. Wait for GitHub Actions (check Actions tab)
# 4. Release appears automatically at /releases
```

Use [Semantic Versioning](https://semver.org/): `v<MAJOR>.<MINOR>.<PATCH>`

## 🔧 Maintenance

### Adding Dependencies

Edit `ci.yml`:
```yaml
- name: Install dependencies
  run: |
    sudo apt-get install -y NEW_PACKAGE
```

### Changing Build Steps

Both workflows use the same build process defined in the project `Makefile`:

1. Generate `vmlinux.h` from kernel BTF
2. Compile BPF program with clang
3. Generate BPF skeleton with bpftool
4. Build test binaries

Modify the `Makefile` to change build steps.

### Updating act Configuration

Edit [`../.actrc`](../.actrc) to change:
- Docker images used
- Environment variables
- Default flags

### Modifying Release Content

Edit `release.yml`:
```yaml
- name: Create release package
  run: |
    # Add/remove files here
    cp NEW_FILE release/${PKG_NAME}/
```

## 🐛 Troubleshooting

### Workflow Fails in CI

1. Check logs in GitHub Actions tab
2. Test locally: `act push`
3. Compare environments
4. Check [ACTIONS.md](ACTIONS.md) troubleshooting section

### Release Not Created

1. Verify tag format: `v*.*.*`
2. Check tag pushed: `git ls-remote --tags origin`
3. Check workflow runs: `gh run list`
4. See [QUICKSTART.md](QUICKSTART.md) troubleshooting

### act Doesn't Work

1. Check Docker: `docker ps`
2. Pull images: `docker pull catthehacker/ubuntu:act-22.04`
3. Check permissions: `docker run hello-world`
4. Use verbose mode: `act push -v`

## 📊 Workflow Status Badges

Add to your main README.md:

```markdown
![CI](https://github.com/YOUR_ORG/xdp-tun-decap/workflows/CI/badge.svg)
![Release](https://github.com/YOUR_ORG/xdp-tun-decap/workflows/Release/badge.svg)
![GitHub release](https://img.shields.io/github/v/release/YOUR_ORG/xdp-tun-decap)
```

Replace `YOUR_ORG` with your GitHub organization/username.

## 🔗 Resources

**GitHub Actions:**
- [Documentation](https://docs.github.com/en/actions)
- [Workflow Syntax](https://docs.github.com/en/actions/reference/workflow-syntax-for-github-actions)
- [Marketplace](https://github.com/marketplace?type=actions)

**nektos/act:**
- [Repository](https://github.com/nektos/act)
- [User Guide](https://nektosact.com/)
- [Docker Images](https://github.com/catthehacker/docker_images)

**Releases:**
- [GitHub Releases](https://docs.github.com/en/repositories/releasing-projects-on-github)
- [Semantic Versioning](https://semver.org/)
- [Conventional Commits](https://www.conventionalcommits.org/)

## 💡 Best Practices

1. **Test locally first:** Always run `act push` before pushing
2. **Small commits:** Easier to debug CI failures
3. **Clear commit messages:** Used in changelog generation
4. **Tag releases properly:** Use semantic versioning
5. **Review workflows:** Check GitHub Actions tab regularly
6. **Keep dependencies updated:** Security and features
7. **Document changes:** Update CLAUDE.md and README.md

## 🆘 Getting Help

- **Issues:** https://github.com/YOUR_ORG/xdp-tun-decap/issues
- **Discussions:** https://github.com/YOUR_ORG/xdp-tun-decap/discussions
- **act Issues:** https://github.com/nektos/act/issues
- **GitHub Actions Community:** https://github.community/c/actions

## 📝 Contributing

When contributing workflow changes:

1. Test locally with act
2. Document in ACTIONS.md
3. Update QUICKSTART.md if needed
4. Test on real GitHub Actions (use draft PRs)
5. Update this README if structure changes

## 🎓 Learning Resources

New to GitHub Actions?

1. Start with [QUICKSTART.md](QUICKSTART.md)
2. Read [ACTIONS.md](ACTIONS.md)
3. Try running `act -l` and `act push`
4. Make a test branch and push
5. Watch the Actions tab on GitHub
6. Experiment with workflow modifications

---

**Last Updated:** 2026-01-23
**Maintainer:** SRE Team
**Project:** XDP Tunnel Decapsulation
