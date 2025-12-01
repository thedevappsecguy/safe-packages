import json
from typing import List
from ..models import ParsedDependency, ManifestParseResult


def parse_composer_json(content: str) -> ManifestParseResult:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        raise ValueError("Invalid JSON content")

    dependencies: List[ParsedDependency] = []

    # require
    if "require" in data and isinstance(data["require"], dict):
        for name, version in data["require"].items():
            if name == "php":
                continue  # Skip php version requirement
            dependencies.append(
                ParsedDependency(
                    name=name, version=version, is_dev=False, source="require"
                )
            )

    # require-dev
    if "require-dev" in data and isinstance(data["require-dev"], dict):
        for name, version in data["require-dev"].items():
            dependencies.append(
                ParsedDependency(
                    name=name, version=version, is_dev=True, source="require-dev"
                )
            )

    return ManifestParseResult(
        ecosystem="Packagist", dependencies=dependencies, manifest_file="composer.json"
    )


def parse_composer_lock(content: str) -> ManifestParseResult:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        raise ValueError("Invalid JSON content")

    dependencies: List[ParsedDependency] = []

    # packages
    if "packages" in data and isinstance(data["packages"], list):
        for pkg in data["packages"]:
            if "name" in pkg and "version" in pkg:
                dependencies.append(
                    ParsedDependency(
                        name=pkg["name"],
                        version=pkg["version"].replace("v", "", 1)
                        if pkg["version"].startswith("v")
                        else pkg["version"],
                        is_dev=False,
                        source="composer.lock",
                    )
                )

    # packages-dev
    if "packages-dev" in data and isinstance(data["packages-dev"], list):
        for pkg in data["packages-dev"]:
            if "name" in pkg and "version" in pkg:
                dependencies.append(
                    ParsedDependency(
                        name=pkg["name"],
                        version=pkg["version"].replace("v", "", 1)
                        if pkg["version"].startswith("v")
                        else pkg["version"],
                        is_dev=True,
                        source="composer.lock",
                    )
                )

    return ManifestParseResult(
        ecosystem="Packagist", dependencies=dependencies, manifest_file="composer.lock"
    )
