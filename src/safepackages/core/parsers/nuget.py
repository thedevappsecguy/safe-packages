import xml.etree.ElementTree as ET
from typing import List
from ..models import ParsedDependency, ManifestParseResult


def parse_packages_config(content: str) -> ManifestParseResult:
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        raise ValueError("Invalid XML content")

    dependencies: List[ParsedDependency] = []

    # <packages>
    #   <package id="Newtonsoft.Json" version="12.0.3" targetFramework="net472" />
    # </packages>

    for package in root.findall("package"):
        name = package.get("id")
        version = package.get("version")
        dev = package.get("developmentDependency")

        is_dev = dev is not None and dev.lower() == "true"

        if name and version:
            dependencies.append(
                ParsedDependency(name=name, version=version, is_dev=is_dev)
            )

    return ManifestParseResult(
        ecosystem="NuGet", dependencies=dependencies, manifest_file="packages.config"
    )


def parse_csproj(content: str) -> ManifestParseResult:
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        raise ValueError("Invalid XML content")

    dependencies: List[ParsedDependency] = []

    # <ItemGroup>
    #   <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
    # </ItemGroup>

    # Handle namespaces if present, but for now assume simple XML or strip namespaces
    # .csproj usually doesn't have complex namespaces for PackageReference

    for item_group in root.findall("ItemGroup"):
        for package in item_group.findall("PackageReference"):
            name = package.get("Include")
            version = package.get("Version")

            if name and version:
                dependencies.append(
                    ParsedDependency(
                        name=name, version=version, is_dev=False, source=".csproj"
                    )
                )

    return ManifestParseResult(
        ecosystem="NuGet", dependencies=dependencies, manifest_file=".csproj"
    )
