from typing import List
from ..models import ParsedDependency, ManifestParseResult


def parse_go_mod(content: str) -> ManifestParseResult:
    dependencies: List[ParsedDependency] = []

    # Simple regex to find require directives
    # require (
    #     github.com/foo/bar v1.2.3
    # )
    # or require github.com/foo/bar v1.2.3

    in_require_block = False

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue

        if line.startswith("require ("):
            in_require_block = True
            continue

        if line == ")" and in_require_block:
            in_require_block = False
            continue

        if in_require_block:
            parts = line.split()
            if len(parts) >= 2:
                dependencies.append(
                    ParsedDependency(name=parts[0], version=parts[1], is_dev=False)
                )
        elif line.startswith("require "):
            parts = line[8:].strip().split()
            if len(parts) >= 2:
                dependencies.append(
                    ParsedDependency(name=parts[0], version=parts[1], is_dev=False)
                )

    return ManifestParseResult(
        ecosystem="Go", dependencies=dependencies, manifest_file="go.mod"
    )


def parse_go_sum(content: str) -> ManifestParseResult:
    dependencies: List[ParsedDependency] = []
    seen = set()

    for line in content.splitlines():
        parts = line.strip().split()
        if len(parts) < 2:
            continue

        name = parts[0]
        version = parts[1]

        # go.sum contains multiple entries per package (for different purposes)
        # We only want unique package@version combinations
        key = f"{name}@{version}"
        if key in seen:
            continue
        seen.add(key)

        dependencies.append(
            ParsedDependency(
                name=name,
                version=version.replace("v", "", 1)
                if version.startswith("v")
                else version,
                is_dev=False,
                source="go.sum",
            )
        )

    return ManifestParseResult(
        ecosystem="Go", dependencies=dependencies, manifest_file="go.sum"
    )
