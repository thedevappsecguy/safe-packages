import json
from typing import List
from ..models import ParsedDependency, ManifestParseResult


def parse_package_json(content: str) -> ManifestParseResult:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        raise ValueError("Invalid JSON content")

    dependencies: List[ParsedDependency] = []

    # Regular dependencies
    if "dependencies" in data and isinstance(data["dependencies"], dict):
        for name, version in data["dependencies"].items():
            dependencies.append(
                ParsedDependency(
                    name=name, version=version, is_dev=False, source="dependencies"
                )
            )

    # Dev dependencies
    if "devDependencies" in data and isinstance(data["devDependencies"], dict):
        for name, version in data["devDependencies"].items():
            dependencies.append(
                ParsedDependency(
                    name=name, version=version, is_dev=True, source="devDependencies"
                )
            )

    return ManifestParseResult(
        ecosystem="npm", dependencies=dependencies, manifest_file="package.json"
    )


def parse_package_lock(content: str) -> ManifestParseResult:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        raise ValueError("Invalid JSON content")

    dependencies: List[ParsedDependency] = []

    # package-lock.json v2/v3 format
    if "packages" in data and isinstance(data["packages"], dict):
        for path, pkg in data["packages"].items():
            if path == "":
                continue  # Skip root package

            name = pkg.get("name") or path.replace("node_modules/", "")
            version = pkg.get("version")

            if version:
                dependencies.append(
                    ParsedDependency(
                        name=name,
                        version=version,
                        is_dev=pkg.get("dev", False),
                        source="package-lock.json",
                    )
                )

    # package-lock.json v1 format fallback
    elif "dependencies" in data and isinstance(data["dependencies"], dict):
        for name, pkg in data["dependencies"].items():
            version = pkg.get("version")
            if version:
                dependencies.append(
                    ParsedDependency(
                        name=name,
                        version=version,
                        is_dev=pkg.get("dev", False),
                        source="package-lock.json",
                    )
                )

    return ManifestParseResult(
        ecosystem="npm", dependencies=dependencies, manifest_file="package-lock.json"
    )
