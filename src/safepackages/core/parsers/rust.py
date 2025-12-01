import tomllib
from typing import List
from ..models import ParsedDependency, ManifestParseResult


def parse_cargo_toml(content: str) -> ManifestParseResult:
    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError:
        raise ValueError("Invalid TOML content")

    dependencies: List[ParsedDependency] = []

    # Regular dependencies
    if "dependencies" in data and isinstance(data["dependencies"], dict):
        for name, version in data["dependencies"].items():
            if isinstance(version, str):
                dependencies.append(
                    ParsedDependency(
                        name=name, version=version, is_dev=False, source="dependencies"
                    )
                )
            elif isinstance(version, dict) and "version" in version:
                dependencies.append(
                    ParsedDependency(
                        name=name,
                        version=version["version"],
                        is_dev=False,
                        source="dependencies",
                    )
                )

    # Dev dependencies
    if "dev-dependencies" in data and isinstance(data["dev-dependencies"], dict):
        for name, version in data["dev-dependencies"].items():
            if isinstance(version, str):
                dependencies.append(
                    ParsedDependency(
                        name=name,
                        version=version,
                        is_dev=True,
                        source="dev-dependencies",
                    )
                )
            elif isinstance(version, dict) and "version" in version:
                dependencies.append(
                    ParsedDependency(
                        name=name,
                        version=version["version"],
                        is_dev=True,
                        source="dev-dependencies",
                    )
                )

    return ManifestParseResult(
        ecosystem="crates.io", dependencies=dependencies, manifest_file="Cargo.toml"
    )


def parse_cargo_lock(content: str) -> ManifestParseResult:
    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError:
        raise ValueError("Invalid TOML content")

    dependencies: List[ParsedDependency] = []

    if "package" in data and isinstance(data["package"], list):
        for pkg in data["package"]:
            if "name" in pkg and "version" in pkg:
                dependencies.append(
                    ParsedDependency(
                        name=pkg["name"],
                        version=pkg["version"],
                        is_dev=False,  # Cargo.lock doesn't distinguish dev deps easily
                        source="Cargo.lock",
                    )
                )

    return ManifestParseResult(
        ecosystem="crates.io", dependencies=dependencies, manifest_file="Cargo.lock"
    )
