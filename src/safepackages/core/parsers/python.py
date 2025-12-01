import json
import re
from typing import List
from ..models import ParsedDependency, ManifestParseResult


def parse_requirements_txt(content: str) -> ManifestParseResult:
    dependencies: List[ParsedDependency] = []

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Simple parsing for now: name==version
        # TODO: Use a proper parser or regex for more complex cases
        if "==" in line:
            parts = line.split("==")
            name = parts[0].strip()
            version = parts[1].split("#")[0].strip()  # Remove comments
        else:
            # Handle cases like 'package>=1.0' or just 'package'
            # For now, we'll just take the first part as the name and default to latest if no version
            # This is a simplification; a real parser would be better
            parts = (
                line.split(">=")
                if ">=" in line
                else line.split("<=")
                if "<=" in line
                else [line]
            )
            name = parts[0].strip()
            version = "latest"

        dependencies.append(ParsedDependency(name=name, version=version, is_dev=False))

    return ManifestParseResult(
        ecosystem="PyPI", dependencies=dependencies, manifest_file="requirements.txt"
    )


def parse_pipfile_lock(content: str) -> ManifestParseResult:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        raise ValueError("Invalid JSON content")

    dependencies: List[ParsedDependency] = []

    # Default dependencies
    if "default" in data and isinstance(data["default"], dict):
        for name, info in data["default"].items():
            if isinstance(info, dict) and "version" in info:
                dependencies.append(
                    ParsedDependency(
                        name=name,
                        version=info["version"].replace("==", ""),
                        is_dev=False,
                        source="Pipfile.lock",
                    )
                )

    # Dev dependencies
    if "develop" in data and isinstance(data["develop"], dict):
        for name, info in data["develop"].items():
            if isinstance(info, dict) and "version" in info:
                dependencies.append(
                    ParsedDependency(
                        name=name,
                        version=info["version"].replace("==", ""),
                        is_dev=True,
                        source="Pipfile.lock",
                    )
                )

    return ManifestParseResult(
        ecosystem="PyPI", dependencies=dependencies, manifest_file="Pipfile.lock"
    )


def parse_poetry_lock(content: str) -> ManifestParseResult:
    dependencies: List[ParsedDependency] = []

    # Simple TOML-like parsing for poetry.lock
    # We iterate line by line to find [[package]] blocks

    lines = content.splitlines()
    current_package = {}

    for line in lines:
        line = line.strip()

        if line == "[[package]]":
            # Save previous package
            if "name" in current_package and "version" in current_package:
                dependencies.append(
                    ParsedDependency(
                        name=current_package["name"],
                        version=current_package["version"],
                        is_dev=current_package.get("category") == "dev",
                        source="poetry.lock",
                    )
                )
            current_package = {}

        elif line.startswith("name = "):
            match = re.search(r'name = "(.+)"', line)
            if match:
                current_package["name"] = match.group(1)

        elif line.startswith("version = "):
            match = re.search(r'version = "(.+)"', line)
            if match:
                current_package["version"] = match.group(1)

        elif line.startswith("category = "):
            match = re.search(r'category = "(.+)"', line)
            if match:
                current_package["category"] = match.group(1)

    # Save last package
    if "name" in current_package and "version" in current_package:
        dependencies.append(
            ParsedDependency(
                name=current_package["name"],
                version=current_package["version"],
                is_dev=current_package.get("category") == "dev",
                source="poetry.lock",
            )
        )

    return ManifestParseResult(
        ecosystem="PyPI", dependencies=dependencies, manifest_file="poetry.lock"
    )
