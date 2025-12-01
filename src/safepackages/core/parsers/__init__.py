from ..models import ManifestParseResult
from .npm import parse_package_json, parse_package_lock
from .python import parse_requirements_txt, parse_pipfile_lock, parse_poetry_lock
from .rust import parse_cargo_toml, parse_cargo_lock
from .go import parse_go_mod, parse_go_sum
from .ruby import parse_gemfile, parse_gemfile_lock
from .php import parse_composer_json, parse_composer_lock
from .maven import parse_pom_xml
from .nuget import parse_packages_config, parse_csproj


def detect_manifest_type(filename: str) -> str:
    lower = filename.lower()
    if lower.endswith("package.json"):
        return "package.json"
    if lower.endswith("package-lock.json"):
        return "package-lock.json"
    if lower.endswith("requirements.txt"):
        return "requirements.txt"
    if lower.endswith("pipfile.lock"):
        return "Pipfile.lock"
    if lower.endswith("poetry.lock"):
        return "poetry.lock"
    if lower.endswith("cargo.toml"):
        return "Cargo.toml"
    if lower.endswith("cargo.lock"):
        return "Cargo.lock"
    if lower.endswith("go.mod"):
        return "go.mod"
    if lower.endswith("go.sum"):
        return "go.sum"
    if lower.endswith("gemfile"):
        return "Gemfile"
    if lower.endswith("gemfile.lock"):
        return "Gemfile.lock"
    if lower.endswith("composer.json"):
        return "composer.json"
    if lower.endswith("composer.lock"):
        return "composer.lock"
    if lower.endswith("pom.xml"):
        return "pom.xml"
    if lower.endswith("packages.config"):
        return "packages.config"
    if lower.endswith(".csproj"):
        return ".csproj"
    return "unknown"


def parse_manifest(filename: str, content: str) -> ManifestParseResult:
    manifest_type = detect_manifest_type(filename)

    if manifest_type == "package.json":
        return parse_package_json(content)
    elif manifest_type == "package-lock.json":
        return parse_package_lock(content)
    elif manifest_type == "requirements.txt":
        return parse_requirements_txt(content)
    elif manifest_type == "Pipfile.lock":
        return parse_pipfile_lock(content)
    elif manifest_type == "poetry.lock":
        return parse_poetry_lock(content)
    elif manifest_type == "Cargo.toml":
        return parse_cargo_toml(content)
    elif manifest_type == "Cargo.lock":
        return parse_cargo_lock(content)
    elif manifest_type == "go.mod":
        return parse_go_mod(content)
    elif manifest_type == "go.sum":
        return parse_go_sum(content)
    elif manifest_type == "Gemfile":
        return parse_gemfile(content)
    elif manifest_type == "Gemfile.lock":
        return parse_gemfile_lock(content)
    elif manifest_type == "composer.json":
        return parse_composer_json(content)
    elif manifest_type == "composer.lock":
        return parse_composer_lock(content)
    elif manifest_type == "pom.xml":
        return parse_pom_xml(content)
    elif manifest_type == "packages.config":
        return parse_packages_config(content)
    elif manifest_type == ".csproj":
        return parse_csproj(content)
    else:
        raise ValueError(f"Unsupported manifest file: {filename}")
