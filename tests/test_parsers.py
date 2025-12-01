import pytest
from safepackages.core.parsers import parse_manifest
from pathlib import Path
from safepackages.core.parsers.npm import parse_package_lock
from safepackages.core.parsers.python import (
    parse_pipfile_lock,
    parse_poetry_lock,
    parse_requirements_txt,
)
from safepackages.core.parsers.go import parse_go_sum
from safepackages.core.parsers.rust import parse_cargo_lock, parse_cargo_toml
from safepackages.core.parsers.ruby import parse_gemfile_lock
from safepackages.core.parsers.php import parse_composer_lock, parse_composer_json
from safepackages.core.parsers.nuget import parse_csproj, parse_packages_config
from safepackages.core.parsers import detect_manifest_type

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_parse_cargo_toml():
    content = """
    [package]
    name = "test"
    version = "0.1.0"

    [dependencies]
    serde = "1.0"
    tokio = { version = "1.0", features = ["full"] }

    [dev-dependencies]
    pytest = "0.1"
    """
    result = parse_manifest("Cargo.toml", content)
    assert result.ecosystem == "crates.io"
    assert len(result.dependencies) == 3

    deps = {d.name: d for d in result.dependencies}
    assert deps["serde"].version == "1.0"
    assert not deps["serde"].is_dev
    assert deps["tokio"].version == "1.0"
    assert not deps["tokio"].is_dev
    assert deps["pytest"].version == "0.1"
    assert deps["pytest"].is_dev


def test_parse_go_mod():
    content = """
    module example.com/test

    go 1.16

    require (
        github.com/gin-gonic/gin v1.7.2
        github.com/stretchr/testify v1.7.0
    )

    require github.com/google/uuid v1.2.0
    """
    result = parse_manifest("go.mod", content)
    assert result.ecosystem == "Go"
    assert len(result.dependencies) == 3

    deps = {d.name: d for d in result.dependencies}
    assert deps["github.com/gin-gonic/gin"].version == "v1.7.2"
    assert deps["github.com/stretchr/testify"].version == "v1.7.0"
    assert deps["github.com/google/uuid"].version == "v1.2.0"


def test_parse_gemfile():
    content = """
    source 'https://rubygems.org'

    gem 'rails', '6.1.3'
    gem 'pg', '~> 1.2'
    gem 'puma'
    """
    result = parse_manifest("Gemfile", content)
    assert result.ecosystem == "RubyGems"
    assert len(result.dependencies) == 3

    deps = {d.name: d for d in result.dependencies}
    assert deps["rails"].version == "6.1.3"
    assert deps["pg"].version == "~> 1.2"
    assert deps["puma"].version == "latest"


def test_parse_composer_json():
    content = """
    {
        "require": {
            "monolog/monolog": "2.0.*",
            "php": "^7.2"
        },
        "require-dev": {
            "phpunit/phpunit": "^9.5"
        }
    }
    """
    result = parse_manifest("composer.json", content)
    assert result.ecosystem == "Packagist"
    # php dependency should be skipped
    assert len(result.dependencies) == 2

    deps = {d.name: d for d in result.dependencies}
    assert deps["monolog/monolog"].version == "2.0.*"
    assert not deps["monolog/monolog"].is_dev
    assert deps["phpunit/phpunit"].version == "^9.5"
    assert deps["phpunit/phpunit"].is_dev


def test_parse_pom_xml():
    content = """
    <project>
        <dependencies>
            <dependency>
                <groupId>org.springframework</groupId>
                <artifactId>spring-core</artifactId>
                <version>5.3.8</version>
            </dependency>
            <dependency>
                <groupId>junit</groupId>
                <artifactId>junit</artifactId>
                <version>4.13.2</version>
                <scope>test</scope>
            </dependency>
        </dependencies>
    </project>
    """
    result = parse_manifest("pom.xml", content)
    assert result.ecosystem == "Maven"
    assert len(result.dependencies) == 2

    deps = {d.name: d for d in result.dependencies}
    assert deps["org.springframework:spring-core"].version == "5.3.8"
    assert not deps["org.springframework:spring-core"].is_dev
    assert deps["junit:junit"].version == "4.13.2"
    assert deps["junit:junit"].is_dev


def test_parse_packages_config():
    content = """
    <packages>
        <package id="Newtonsoft.Json" version="13.0.1" targetFramework="net45" />
        <package id="NUnit" version="3.13.2" targetFramework="net45" developmentDependency="true" />
    </packages>
    """
    result = parse_manifest("packages.config", content)
    assert result.ecosystem == "NuGet"
    assert len(result.dependencies) == 2

    deps = {d.name: d for d in result.dependencies}
    assert deps["Newtonsoft.Json"].version == "13.0.1"
    assert not deps["Newtonsoft.Json"].is_dev
    assert deps["NUnit"].is_dev


def test_parse_package_lock():
    lock_file = FIXTURES_DIR / "package-lock.json"
    result = parse_package_lock(lock_file.read_text(encoding="utf-8"))
    assert result.ecosystem == "npm"
    assert len(result.dependencies) > 0
    # Check for a known dependency from the fixture
    assert any(d.name == "eslint" for d in result.dependencies)


def test_parse_pipfile_lock():
    lock_file = FIXTURES_DIR / "Pipfile.lock"
    result = parse_pipfile_lock(lock_file.read_text(encoding="utf-8"))
    assert result.ecosystem == "PyPI"
    assert len(result.dependencies) > 0
    assert any(d.name == "requests" for d in result.dependencies)


def test_parse_poetry_lock():
    lock_file = FIXTURES_DIR / "poetry.lock"
    result = parse_poetry_lock(lock_file.read_text(encoding="utf-8"))
    assert result.ecosystem == "PyPI"
    assert len(result.dependencies) > 0
    assert any(d.name == "flask" for d in result.dependencies)


def test_parse_go_sum():
    lock_file = FIXTURES_DIR / "go.sum"
    result = parse_go_sum(lock_file.read_text(encoding="utf-8"))
    assert result.ecosystem == "Go"
    assert len(result.dependencies) > 0
    assert any(d.name == "github.com/gin-gonic/gin" for d in result.dependencies)


def test_parse_cargo_lock():
    lock_file = FIXTURES_DIR / "Cargo.lock"
    result = parse_cargo_lock(lock_file.read_text(encoding="utf-8"))
    assert result.ecosystem == "crates.io"
    assert len(result.dependencies) > 0
    assert any(d.name == "serde" for d in result.dependencies)


def test_parse_gemfile_lock():
    lock_file = FIXTURES_DIR / "Gemfile.lock"
    result = parse_gemfile_lock(lock_file.read_text(encoding="utf-8"))
    assert result.ecosystem == "RubyGems"
    assert len(result.dependencies) > 0
    assert any(d.name == "rails" for d in result.dependencies)


def test_parse_composer_lock():
    lock_file = FIXTURES_DIR / "composer.lock"
    result = parse_composer_lock(lock_file.read_text(encoding="utf-8"))
    assert result.ecosystem == "Packagist"
    assert len(result.dependencies) > 0
    assert any(d.name == "monolog/monolog" for d in result.dependencies)


def test_parse_csproj():
    lock_file = FIXTURES_DIR / "test.csproj"
    result = parse_csproj(lock_file.read_text(encoding="utf-8"))
    assert result.ecosystem == "NuGet"
    assert len(result.dependencies) > 0
    assert any(d.name == "Newtonsoft.Json" for d in result.dependencies)


def test_parse_maven_scope():
    content = """
    <project>
        <dependencies>
            <dependency>
                <groupId>g</groupId>
                <artifactId>a</artifactId>
                <version>1.0</version>
                <scope>test</scope>
            </dependency>
            <dependency>
                <groupId>g</groupId>
                <artifactId>b</artifactId>
                <version>1.0</version>
                <scope>compile</scope>
            </dependency>
        </dependencies>
    </project>
    """
    result = parse_manifest("pom.xml", content)
    deps = {d.name: d for d in result.dependencies}
    assert deps["g:a"].is_dev is True
    assert deps["g:b"].is_dev is False


def test_parse_npm_lock_v2_complex():
    content = """
    {
        "name": "root",
        "version": "1.0.0",
        "lockfileVersion": 2,
        "packages": {
            "": {"name": "root"},
            "node_modules/a": {"version": "1.0.0"},
            "node_modules/b": {"version": "2.0.0", "dev": true}
        }
    }
    """
    result = parse_package_lock(content)
    deps = {d.name: d for d in result.dependencies}
    assert deps["a"].version == "1.0.0"
    assert deps["a"].is_dev is False
    assert deps["b"].version == "2.0.0"
    assert deps["b"].version == "2.0.0"
    assert deps["b"].is_dev is True


def test_parse_maven_namespaces():
    content = """
    <project xmlns="http://maven.apache.org/POM/4.0.0">
        <dependencies>
            <dependency>
                <groupId>com.example</groupId>
                <artifactId>test</artifactId>
                <version>1.0.0</version>
            </dependency>
        </dependencies>
    </project>
    """
    result = parse_manifest("pom.xml", content)
    assert len(result.dependencies) == 1
    assert result.dependencies[0].name == "com.example:test"


def test_parse_maven_invalid():
    with pytest.raises(ValueError):
        parse_manifest("pom.xml", "<invalid>")


def test_parse_npm_invalid_json():
    with pytest.raises(ValueError):
        parse_manifest("package.json", "{invalid")
    with pytest.raises(ValueError):
        parse_manifest("package-lock.json", "{invalid")


def test_parse_npm_lock_v1_simple():
    content = """
    {
        "name": "root",
        "version": "1.0.0",
        "dependencies": {
            "a": {
                "version": "1.0.0",
                "dev": false
            },
            "b": {
                "version": "2.0.0",
                "dev": true
            }
        }
    }
    """
    result = parse_package_lock(content)
    deps = {d.name: d for d in result.dependencies}
    assert deps["a"].version == "1.0.0"
    assert deps["a"].is_dev is False
    assert deps["b"].version == "2.0.0"
    assert deps["b"].is_dev is True


def test_parse_maven_iterparse_error(mocker):
    content = "<project></project>"
    # Mock ET.iterparse to raise Exception
    mocker.patch(
        "xml.etree.ElementTree.iterparse", side_effect=Exception("Iterparse failed")
    )

    result = parse_manifest("pom.xml", content)
    result = parse_manifest("pom.xml", content)
    assert result.ecosystem == "Maven"
    assert len(result.dependencies) == 0


# --- Parser Detection Tests ---


def test_detect_manifest_type():
    assert detect_manifest_type("package.json") == "package.json"
    assert detect_manifest_type("package-lock.json") == "package-lock.json"
    assert detect_manifest_type("requirements.txt") == "requirements.txt"
    assert detect_manifest_type("Pipfile.lock") == "Pipfile.lock"
    assert detect_manifest_type("poetry.lock") == "poetry.lock"
    assert detect_manifest_type("Cargo.toml") == "Cargo.toml"
    assert detect_manifest_type("Cargo.lock") == "Cargo.lock"
    assert detect_manifest_type("go.mod") == "go.mod"
    assert detect_manifest_type("go.sum") == "go.sum"
    assert detect_manifest_type("Gemfile") == "Gemfile"
    assert detect_manifest_type("Gemfile.lock") == "Gemfile.lock"
    assert detect_manifest_type("composer.json") == "composer.json"
    assert detect_manifest_type("composer.lock") == "composer.lock"
    assert detect_manifest_type("pom.xml") == "pom.xml"
    assert detect_manifest_type("packages.config") == "packages.config"
    assert detect_manifest_type("test.csproj") == ".csproj"
    assert detect_manifest_type("unknown.txt") == "unknown"


def test_parse_manifest_unsupported():
    with pytest.raises(ValueError):
        parse_manifest("unknown.txt", "")


def test_parse_manifest_dispatch(mocker):
    # Mock all parsers to verify dispatch
    mocker.patch("safepackages.core.parsers.parse_package_json")
    mocker.patch("safepackages.core.parsers.parse_package_lock")
    mocker.patch("safepackages.core.parsers.parse_requirements_txt")
    mocker.patch("safepackages.core.parsers.parse_pipfile_lock")
    mocker.patch("safepackages.core.parsers.parse_poetry_lock")
    mocker.patch("safepackages.core.parsers.parse_cargo_toml")
    mocker.patch("safepackages.core.parsers.parse_cargo_lock")
    mocker.patch("safepackages.core.parsers.parse_go_mod")
    mocker.patch("safepackages.core.parsers.parse_go_sum")
    mocker.patch("safepackages.core.parsers.parse_gemfile")
    mocker.patch("safepackages.core.parsers.parse_gemfile_lock")
    mocker.patch("safepackages.core.parsers.parse_composer_json")
    mocker.patch("safepackages.core.parsers.parse_composer_lock")
    mocker.patch("safepackages.core.parsers.parse_pom_xml")
    mocker.patch("safepackages.core.parsers.parse_packages_config")
    mocker.patch("safepackages.core.parsers.parse_csproj")

    from safepackages.core.parsers import (
        parse_package_json,
        parse_package_lock,
        parse_requirements_txt,
        parse_pipfile_lock,
        parse_poetry_lock,
        parse_cargo_toml,
        parse_cargo_lock,
        parse_go_mod,
        parse_go_sum,
        parse_gemfile,
        parse_gemfile_lock,
        parse_composer_json,
        parse_composer_lock,
        parse_pom_xml,
        parse_packages_config,
        parse_csproj,
    )

    parse_manifest("package.json", "")
    parse_package_json.assert_called_once()

    parse_manifest("package-lock.json", "")
    parse_package_lock.assert_called_once()

    parse_manifest("requirements.txt", "")
    parse_requirements_txt.assert_called_once()

    parse_manifest("Pipfile.lock", "")
    parse_pipfile_lock.assert_called_once()

    parse_manifest("poetry.lock", "")
    parse_poetry_lock.assert_called_once()

    parse_manifest("Cargo.toml", "")
    parse_cargo_toml.assert_called_once()

    parse_manifest("Cargo.lock", "")
    parse_cargo_lock.assert_called_once()

    parse_manifest("go.mod", "")
    parse_go_mod.assert_called_once()

    parse_manifest("go.sum", "")
    parse_go_sum.assert_called_once()

    parse_manifest("Gemfile", "")
    parse_gemfile.assert_called_once()

    parse_manifest("Gemfile.lock", "")
    parse_gemfile_lock.assert_called_once()

    parse_manifest("composer.json", "")
    parse_composer_json.assert_called_once()

    parse_manifest("composer.lock", "")
    parse_composer_lock.assert_called_once()

    parse_manifest("pom.xml", "")
    parse_pom_xml.assert_called_once()

    parse_manifest("packages.config", "")
    parse_packages_config.assert_called_once()

    parse_manifest("test.csproj", "")
    parse_csproj.assert_called_once()


# --- Parser Coverage Tests ---


def test_rust_cargo_toml_dict_version():
    content = """
    [dependencies]
    serde = { version = "1.0" }
    
    [dev-dependencies]
    tokio = { version = "1.0" }
    """
    result = parse_cargo_toml(content)
    deps = {d.name: d for d in result.dependencies}
    assert deps["serde"].version == "1.0"
    assert deps["tokio"].version == "1.0"
    assert deps["tokio"].is_dev is True


def test_rust_cargo_lock_invalid():
    with pytest.raises(ValueError):
        parse_cargo_lock("invalid")


def test_rust_cargo_lock_missing_fields():
    content = """
    [[package]]
    name = "test"
    # missing version
    """
    result = parse_cargo_lock(content)
    assert len(result.dependencies) == 0


def test_nuget_invalid_xml():
    with pytest.raises(ValueError):
        parse_packages_config("<invalid")
    with pytest.raises(ValueError):
        parse_csproj("<invalid")


def test_nuget_packages_config_dev_false():
    content = """
    <packages>
        <package id="A" version="1.0" developmentDependency="false" />
    </packages>
    """
    result = parse_packages_config(content)
    assert result.dependencies[0].is_dev is False


def test_php_invalid_json():
    with pytest.raises(ValueError):
        parse_composer_json("{invalid")
    with pytest.raises(ValueError):
        parse_composer_lock("{invalid")


def test_php_composer_lock_version_v_prefix():
    content = """
    {
        "packages": [
            {"name": "p1", "version": "v1.0.0"}
        ],
        "packages-dev": [
            {"name": "p2", "version": "v2.0.0"}
        ]
    }
    """
    result = parse_composer_lock(content)
    deps = {d.name: d for d in result.dependencies}
    assert deps["p1"].version == "1.0.0"
    assert deps["p2"].version == "2.0.0"


def test_requirements_txt_edge_cases():
    content = """
    # Comment
    package-a
    package-b>=1.0
    package-c<=2.0
    """
    result = parse_requirements_txt(content)
    deps = {d.name: d for d in result.dependencies}

    assert deps["package-a"].version == "latest"
    assert deps["package-b"].version == "latest"  # Parser simplification
    assert deps["package-c"].version == "latest"  # Parser simplification


def test_poetry_lock_category():
    content = """
    [[package]]
    name = "main-lib"
    version = "1.0.0"
    category = "main"
    
    [[package]]
    name = "dev-lib"
    version = "2.0.0"
    category = "dev"
    """
    result = parse_poetry_lock(content)
    deps = {d.name: d for d in result.dependencies}

    assert deps["main-lib"].is_dev is False
    assert deps["dev-lib"].is_dev is True
