# SafePackages
[![CodeQL](https://github.com/thedevappsecguy/safe-packages/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/thedevappsecguy/safe-packages/actions/workflows/github-code-scanning/codeql) [![CI](https://github.com/thedevappsecguy/safe-packages/actions/workflows/ci.yml/badge.svg)](https://github.com/thedevappsecguy/safe-packages/actions/workflows/ci.yml) [![Publish to PyPI](https://github.com/thedevappsecguy/safe-packages/actions/workflows/release.yml/badge.svg)](https://github.com/thedevappsecguy/safe-packages/actions/workflows/release.yml) [![Publish to TestPyPI](https://github.com/thedevappsecguy/safe-packages/actions/workflows/publish-testpypi.yml/badge.svg)](https://github.com/thedevappsecguy/safe-packages/actions/workflows/publish-testpypi.yml) [![GitHub Actions Security Analysis with zizmor 🌈](https://github.com/thedevappsecguy/safe-packages/actions/workflows/zizmor.yml/badge.svg)](https://github.com/thedevappsecguy/safe-packages/actions/workflows/zizmor.yml)

**SafePackages** is a powerful Python CLI tool designed to scan your project's dependencies for known vulnerabilities. It leverages the [OSV (Open Source Vulnerabilities)](https://osv.dev/) database to provide accurate and up-to-date security information for a wide range of ecosystems.

## Features

*   **Multi-Mode Scanning**:
    *   **Single Package**: Scan a specific package version.
    *   **Manifest File**: Parse and scan dependency files (e.g., `requirements.txt`, `package.json`).
    *   **Batch Mode**: Scan a list of packages from a JSON input.
*   **Broad Ecosystem Support**: Supports npm, PyPI, Maven, NuGet, Go, Rust, PHP (Composer), Ruby (Gems), and more.
*   **Flexible Output**: Generate reports in **Table**, **JSON**, or **CSV** formats.
*   **CI/CD Ready**:
    *   Set failure thresholds (e.g., fail only on `CRITICAL` or `HIGH` severity).
    *   Exit codes for pipeline integration.
*   **Dev Dependency Control**: Option to include or exclude development dependencies.

## Installation

You can install SafePackages using pip:

```bash
pip install safe-packages
```

Or using uv:

```bash
uv pip install safe-packages
```

## Usage

After installation, the `safepackages` command will be available. You can see the help message by running:

```bash
safepackages --help
```

### Commands

SafePackages provides three main commands:

#### 1. `scan` - Scan a Single Package

Scan a specific package version for vulnerabilities.

**Usage:**
```bash
safepackages scan [OPTIONS] NAME
```

**Arguments:**
*   `NAME`: The name of the package to scan (Required).

**Options:**
*   `-e, --ecosystem TEXT`: Package ecosystem (e.g., npm, PyPI, Maven, NuGet) (Required).
*   `-v, --version TEXT`: Package version to check.
*   `-f, --format [table|json|csv]`: Output format (Default: table).
*   `-o, --output TEXT`: Write output to a file.
*   `--fail-on [low|medium|high|critical]`: Exit with error code 1 if vulnerabilities of this severity or higher are found (Default: high).

**Example:**
```bash
safepackages scan requests --version 2.20.0 --ecosystem PyPI
```

#### 2. `file` - Scan a Manifest File

Scan a dependency manifest file. The file type is automatically detected.

**Usage:**
```bash
safepackages file [OPTIONS] FILE_PATH
```

**Arguments:**
*   `FILE_PATH`: Path to the manifest file (Required).

**Options:**
*   `--include-dev`: Include development dependencies in the scan.
*   `-f, --format [table|json|csv]`: Output format (Default: table).
*   `-o, --output TEXT`: Write output to a file.
*   `--fail-on [low|medium|high|critical]`: Exit with error code 1 if vulnerabilities of this severity or higher are found (Default: high).

**Supported Manifests:**
*   `requirements.txt`, `poetry.lock`, `Pipfile.lock` (Python)
*   `package.json`, `package-lock.json` (npm)
*   `yarn.lock` (yarn)
*   `pom.xml` (Maven)
*   `go.mod` (Go)
*   `Cargo.lock` (Rust)
*   `Gemfile.lock` (Ruby)
*   `composer.lock` (PHP)
*   `packages.config`, `*.csproj` (NuGet)

**Example:**
```bash
safepackages file requirements.txt --include-dev --format json
```

#### 3. `batch` - Batch Scan

Scan a list of packages from a JSON input string or file.

**Usage:**
```bash
safepackages batch [OPTIONS] JSON_INPUT
```

**Arguments:**
*   `JSON_INPUT`: A JSON string array of packages or a path to a JSON file (Required).
    *   Format: `[{"name": "pkg_name", "version": "1.0.0", "ecosystem": "PyPI"}, ...]`

**Options:**
*   `-f, --format [table|json|csv]`: Output format (Default: table).
*   `-o, --output TEXT`: Write output to a file.
*   `--fail-on [low|medium|high|critical]`: Exit with error code 1 if vulnerabilities of this severity or higher are found (Default: high).

**Example:**
```bash
# From JSON string
safepackages batch '[{"name":"django","version":"3.0.0","ecosystem":"PyPI"}]'

# From JSON file
safepackages batch packages.json
```

## Security

SafePackages prioritizes security and reliability through several modern practices:

*   **Pydantic for Data Validation**: extensive use of [Pydantic](https://docs.pydantic.dev/) ensures robust data parsing and validation, preventing many common injection and data integrity issues.
*   **Automated Security Scans**:
    *   **CodeQL**: [GitHub's CodeQL](https://codeql.github.com/) static analysis engine scans every commit for vulnerabilities.
    *   **Zizmor**: [zizmor](https://github.com/woodruffw/zizmor) is used to statically analyze GitHub Actions workflows for security misconfigurations.
*   **Supply Chain Security**:
    *   **Immutable Releases**: immutability, adding a new layer of supply chain security. With immutable releases, assets and tags are protected from tampering after publication.
    *   **Trusted Publishing**: Uses PyPI's [Trusted Publishing](https://docs.pypi.org/trusted-publishing/) model, eliminating long-lived secrets.
    *   **Build Provenance**: All releases include [SLSA](https://slsa.dev/) build provenance attestations, signed by GitHub's certificate authority. You can [verify these attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations#verifying-an-artifact-attestation-for-binaries) to confirm artifacts were built in the authenticated CI environment:
        1. Download the artifact (e.g., from PyPI):
           ```bash
           pip download safe-packages --no-deps
           ```
        2. Verify the attestation:
           ```bash
           gh attestation verify PATH/TO/BUILD/ARTIFACT-BINARY -R thedevappsecguy/safe-packages
           ```

## Development

We use `uv` and `poethepoet` for development.

1.  Install `uv`: https://github.com/astral-sh/uv
2.  Run tasks:
    *   `uv run poe check` - Run full verification (lint, test, build).
    *   `uv run poe list` - List all available tasks.

## License

[Apache 2.0 License](LICENSE)
