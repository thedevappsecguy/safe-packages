import re
from typing import List
from ..models import ParsedDependency, ManifestParseResult


def parse_gemfile(content: str) -> ManifestParseResult:
    dependencies: List[ParsedDependency] = []

    # Simple regex for Gemfile
    # gem 'rails', '5.0.0'
    # gem "rails", "5.0.0"

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Match gem 'name', 'version'
        match = re.search(
            r"^gem\s+['\"]([^'\"]+)['\"](?:,\s*['\"]([^'\"]+)['\"])?", line
        )
        if match:
            name = match.group(1)
            version = match.group(2) or "latest"  # Default if no version specified

            dependencies.append(
                ParsedDependency(name=name, version=version, is_dev=False)
            )

    return ManifestParseResult(
        ecosystem="RubyGems", dependencies=dependencies, manifest_file="Gemfile"
    )


def parse_gemfile_lock(content: str) -> ManifestParseResult:
    dependencies: List[ParsedDependency] = []
    in_specs = False

    for line in content.splitlines():
        line_stripped = line.strip()

        if line_stripped == "specs:":
            in_specs = True
            continue

        if in_specs and line.strip() == "":
            in_specs = False
            continue

        if in_specs and line.startswith("    ") and not line.startswith("      "):
            # Match gem (version)
            match = re.search(r"^\s+([a-zA-Z0-9_-]+)\s+\(([^)]+)\)", line)
            if match:
                dependencies.append(
                    ParsedDependency(
                        name=match.group(1),
                        version=match.group(2),
                        is_dev=False,
                        source="Gemfile.lock",
                    )
                )

    return ManifestParseResult(
        ecosystem="RubyGems", dependencies=dependencies, manifest_file="Gemfile.lock"
    )
