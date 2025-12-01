import io
import xml.etree.ElementTree as ET
from typing import List
from ..models import ParsedDependency, ManifestParseResult


def parse_pom_xml(content: str) -> ManifestParseResult:
    try:
        # Remove namespace to simplify parsing
        # Simple hack: remove xmlns="..." attributes
        # A better way is to handle namespaces properly, but for now let's try to be robust
        # or just use local-name() in xpath if lxml was used, but we use stdlib.
        # Let's just strip namespaces from tags

        it = ET.iterparse(io.StringIO(content))
        for _, el in it:
            if "}" in el.tag:
                el.tag = el.tag.split("}", 1)[1]  # strip all namespaces
        root = it.root
    except Exception:
        # Fallback to standard parsing if iterparse fails or just parse string directly
        # If content has namespaces, findall might need namespace map.
        # Let's try simple parsing first.
        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            raise ValueError("Invalid XML content")

    dependencies: List[ParsedDependency] = []

    # Helper to handle namespaces if present in root
    ns = {}
    if "}" in root.tag:
        ns_url = root.tag.split("}")[0].strip("{")
        ns = {"m": ns_url}

    def find_all(element, path):
        if ns:
            # Add namespace prefix to path elements
            # e.g. "dependencies/dependency" -> "m:dependencies/m:dependency"
            parts = path.split("/")
            ns_path = "/".join(f"m:{p}" for p in parts)
            return element.findall(ns_path, ns)
        return element.findall(path)

    def find_text(element, path):
        if ns:
            parts = path.split("/")
            ns_path = "/".join(f"m:{p}" for p in parts)
            el = element.find(ns_path, ns)
            return el.text if el is not None else None
        el = element.find(path)
        return el.text if el is not None else None

    # Parse dependencies
    for dep in find_all(root, "dependencies/dependency"):
        group_id = find_text(dep, "groupId")
        artifact_id = find_text(dep, "artifactId")
        version = find_text(dep, "version")
        scope = find_text(dep, "scope")
        if group_id and artifact_id and version:
            # Maven packages in OSV are usually "groupId:artifactId"
            name = f"{group_id}:{artifact_id}"

            # Check for property placeholders in version e.g. ${project.version}
            # We can't resolve them without full context, so we might skip or keep as is.
            # For now, keep as is.

            is_dev = scope == "test"

            dependencies.append(
                ParsedDependency(name=name, version=version, is_dev=is_dev)
            )
    return ManifestParseResult(
        ecosystem="Maven", dependencies=dependencies, manifest_file="pom.xml"
    )
