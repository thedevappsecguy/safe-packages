import sys
import subprocess
import shutil
import os
import glob


def run(cmd, check=True):
    print(f"Running: {cmd}")
    ret = subprocess.run(cmd, shell=True)
    if check and ret.returncode != 0:
        sys.exit(ret.returncode)


def e2e():
    print("Running SafePackages E2E Verification...")

    print("\n1. CLI Basics")
    run("uv run safepackages --help")

    print("\n2. Scan Single Package")
    # These are expected to find vulnerabilities (exit code 1), so check=False
    run("uv run safepackages scan lodash -e npm -v 4.17.19", check=False)
    run(
        "uv run safepackages scan requests -e PyPI -v 2.20.0 --format json", check=False
    )

    print("\n3. Scan Manifest Files")
    files = [
        "tests/fixtures/package.json",
        "tests/fixtures/requirements.txt",
        "tests/fixtures/Cargo.toml",
        "tests/fixtures/go.mod",
        "tests/fixtures/Gemfile",
        "tests/fixtures/composer.json",
        "tests/fixtures/pom.xml",
        "tests/fixtures/packages.config",
        "tests/fixtures/test.csproj",
        "tests/fixtures/package-lock.json",
        "tests/fixtures/Pipfile.lock",
        "tests/fixtures/poetry.lock",
        "tests/fixtures/go.sum",
        "tests/fixtures/Cargo.lock",
        "tests/fixtures/Gemfile.lock",
        "tests/fixtures/composer.lock",
    ]
    for f in files:
        run(f'uv run safepackages file "{f}"', check=False)

    print("\n4. Batch Scan")
    run(
        'uv run safepackages batch \'[{"name":"lodash","ecosystem":"npm","version":"4.17.19"},{"name":"requests","ecosystem":"PyPI","version":"2.20.0"}]\'',
        check=False,
    )
    run('uv run safepackages batch "tests/fixtures/batch-input.json"', check=False)

    print("\n5. Output Formats")
    run(
        'uv run safepackages file "tests/fixtures/package.json" --format csv',
        check=False,
    )
    run(
        'uv run safepackages file "tests/fixtures/package.json" --format json',
        check=False,
    )

    print("\n6. Advanced Options")
    run(
        'uv run safepackages file "tests/fixtures/package.json" --include-dev',
        check=False,
    )
    run(
        'uv run safepackages file "tests/fixtures/package-lock.json" --fail-on low',
        check=False,
    )

    print("Testing Scan with Output File (JSON)...")
    if os.path.exists("scan_results.json"):
        os.remove("scan_results.json")
    run(
        "uv run safepackages scan lodash -e npm -v 4.17.19 --format json --output scan_results.json",
        check=False,
    )
    if os.path.exists("scan_results.json"):
        print("[SUCCESS] scan_results.json created.")
    else:
        print("[FAILURE] scan_results.json NOT created.")
        sys.exit(1)

    print("Testing Batch with Output File (CSV)...")
    if os.path.exists("batch_results.csv"):
        os.remove("batch_results.csv")
    run(
        'uv run safepackages batch "tests/fixtures/batch-input.json" --format csv --output batch_results.csv',
        check=False,
    )
    if os.path.exists("batch_results.csv"):
        print("[SUCCESS] batch_results.csv created.")
    else:
        print("[FAILURE] batch_results.csv NOT created.")
        sys.exit(1)

    print("\nE2E Verification Complete!")


def clean():
    print("Cleaning project...")

    # Remove PyCache
    for root, dirs, files in os.walk("."):
        for d in dirs:
            if d == "__pycache__":
                shutil.rmtree(os.path.join(root, d))

    # Remove Build Artifacts
    dirs_to_remove = ["build", "dist", ".pytest_cache", "htmlcov"]
    for d in dirs_to_remove:
        if os.path.exists(d):
            shutil.rmtree(d)

    # Remove *.egg-info
    for d in glob.glob("*.egg-info"):
        shutil.rmtree(d)

    # Remove files
    files_to_remove = [".coverage", "scan_results.json", "batch_results.csv"]
    for f in files_to_remove:
        if os.path.exists(f):
            os.remove(f)

    print("Clean complete.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python tasks/tasks.py [e2e|clean]")
        sys.exit(1)

    task = sys.argv[1]
    if task == "e2e":
        e2e()
    elif task == "clean":
        clean()
    else:
        print(f"Unknown task: {task}")
        sys.exit(1)
