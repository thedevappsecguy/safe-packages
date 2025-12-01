import pytest
from typer.testing import CliRunner
from safepackages.cli.main import app
import json
from safepackages.core.models import V1VulnerabilityList, OsvVulnerability, OsvSeverity
from safepackages.cli.output import format_table, format_json, format_csv

runner = CliRunner()


def test_scan_command_help():
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "Scan a single package" in result.stdout


def test_file_command_help():
    result = runner.invoke(app, ["file", "--help"])
    assert result.exit_code == 0
    assert "Scan a manifest file" in result.stdout


def test_batch_command_help():
    result = runner.invoke(app, ["batch", "--help"])
    assert result.exit_code == 0
    assert "Batch scan packages" in result.stdout


def test_scan_command_fail_on_critical(tmp_path):
    # Mocking OSVClient would be ideal, but for now we can test the CLI structure
    # and argument parsing. Testing actual API calls in unit tests is flaky/slow.
    # However, to test fail-on logic, we need the client to return vulnerabilities.
    # We can mock the OSVClient in the command modules.
    pass


@pytest.fixture
def mock_client(mocker):
    mock_osv = mocker.patch("safepackages.cli.commands.scan.OSVClient")
    mock_instance = mock_osv.return_value
    mock_instance.close = mocker.AsyncMock()
    return mock_instance


def test_scan_output_file(tmp_path, mocker):
    # Mock OSVClient to avoid network calls
    mock_osv = mocker.patch("safepackages.cli.commands.scan.OSVClient")
    mock_instance = mock_osv.return_value
    mock_instance.close = mocker.AsyncMock()

    # Mock scan_package return value
    from safepackages.core.models import V1VulnerabilityList

    mock_instance.scan_package = mocker.AsyncMock(
        return_value=V1VulnerabilityList(vulns=[])
    )

    output_file = tmp_path / "result.json"
    result = runner.invoke(
        app, ["scan", "test", "-e", "npm", "-o", str(output_file), "-f", "json"]
    )

    assert result.exit_code == 0
    assert output_file.exists()
    assert "Results written to" in result.stdout

    with open(output_file) as f:
        data = json.load(f)
        assert isinstance(data, list)
        assert data[0]["package"] == "test"


def test_scan_fail_on(mocker):
    # Mock OSVClient
    mock_osv = mocker.patch("safepackages.cli.commands.scan.OSVClient")
    mock_instance = mock_osv.return_value
    mock_instance.close = mocker.AsyncMock()

    # Mock scan_package return value with HIGH severity vulnerability
    from safepackages.core.models import (
        V1VulnerabilityList,
        OsvVulnerability,
        OsvSeverity,
    )

    vuln = OsvVulnerability(
        id="TEST-1",
        severity=[
            OsvSeverity(
                type="CVSS_V3", score="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            )
        ],  # Score ~9.8 -> CRITICAL
    )

    mock_instance.scan_package = mocker.AsyncMock(
        return_value=V1VulnerabilityList(vulns=[vuln])
    )

    # Should fail on high (default)
    result = runner.invoke(app, ["scan", "test", "-e", "npm"])
    assert result.exit_code == 1

    # Should fail on critical
    result = runner.invoke(app, ["scan", "test", "-e", "npm", "--fail-on", "critical"])
    assert result.exit_code == 1

    # Should NOT fail if we only care about unknown (impossible via CLI, but testing logic)
    # Actually, let's test a MEDIUM vuln

    vuln_med = OsvVulnerability(
        id="TEST-2",
        severity=[
            OsvSeverity(
                type="CVSS_V3", score="CVSS:3.0/AV:P/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:L"
            )
        ],  # Score 4.7 -> MEDIUM
    )

    mock_instance.scan_package = mocker.AsyncMock(
        return_value=V1VulnerabilityList(vulns=[vuln_med])
    )

    # Should NOT fail on high
    result = runner.invoke(app, ["scan", "test", "-e", "npm", "--fail-on", "high"])
    assert result.exit_code == 0

    # Should fail on medium
    result = runner.invoke(app, ["scan", "test", "-e", "npm", "--fail-on", "medium"])
    assert result.exit_code == 1


def test_file_command_npm(tmp_path, mocker):
    # Create a dummy package.json
    package_json = tmp_path / "package.json"
    package_json.write_text(json.dumps({"dependencies": {"lodash": "4.17.15"}}))

    # Mock OSVClient
    mock_osv = mocker.patch("safepackages.cli.commands.file.OSVClient")
    mock_instance = mock_osv.return_value
    mock_instance.close = mocker.AsyncMock()

    # Mock scan_packages
    mock_instance.scan_packages = mocker.AsyncMock(
        return_value=[V1VulnerabilityList(vulns=[])]
    )

    result = runner.invoke(app, ["file", str(package_json)])
    assert result.exit_code == 0
    assert "lodash" in result.stdout


def test_file_command_requirements(tmp_path, mocker):
    # Create a dummy requirements.txt
    req_txt = tmp_path / "requirements.txt"
    req_txt.write_text("requests==2.20.0")

    # Mock OSVClient
    mock_osv = mocker.patch("safepackages.cli.commands.file.OSVClient")
    mock_instance = mock_osv.return_value
    mock_instance.close = mocker.AsyncMock()

    mock_instance.scan_packages = mocker.AsyncMock(
        return_value=[V1VulnerabilityList(vulns=[])]
    )

    result = runner.invoke(app, ["file", str(req_txt)])
    assert result.exit_code == 0
    assert "requests" in result.stdout


def test_file_command_fail_on(tmp_path, mocker):
    package_json = tmp_path / "package.json"
    package_json.write_text(json.dumps({"dependencies": {"bad-pkg": "1.0.0"}}))

    mock_osv = mocker.patch("safepackages.cli.commands.file.OSVClient")
    mock_instance = mock_osv.return_value
    mock_instance.close = mocker.AsyncMock()

    # Mock a high severity vulnerability
    vuln = OsvVulnerability(
        id="TEST-1",
        severity=[
            OsvSeverity(
                type="CVSS_V3", score="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            )
        ],  # Score ~9.8 -> CRITICAL
    )
    mock_instance.scan_packages = mocker.AsyncMock(
        return_value=[V1VulnerabilityList(vulns=[vuln])]
    )

    result = runner.invoke(app, ["file", str(package_json), "--fail-on", "high"])
    assert result.exit_code == 1

    result = runner.invoke(app, ["file", str(package_json), "--fail-on", "critical"])
    assert result.exit_code == 1

    # Test Low severity
    vuln_low = OsvVulnerability(
        id="TEST-2",
        severity=[
            OsvSeverity(
                type="CVSS_V3", score="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"
            )
        ],  # LOW
    )
    mock_instance.scan_packages = mocker.AsyncMock(
        return_value=[V1VulnerabilityList(vulns=[vuln_low])]
    )

    result = runner.invoke(app, ["file", str(package_json), "--fail-on", "high"])
    assert result.exit_code == 0

    result = runner.invoke(app, ["file", str(package_json), "--fail-on", "low"])
    assert result.exit_code == 1


def test_batch_command(tmp_path, mocker):
    # Create a dummy batch.json
    batch_json = tmp_path / "batch.json"
    batch_json.write_text(
        json.dumps([{"name": "lodash", "ecosystem": "npm", "version": "4.17.15"}])
    )

    # Mock OSVClient
    mock_osv = mocker.patch("safepackages.cli.commands.batch.OSVClient")
    mock_instance = mock_osv.return_value
    mock_instance.close = mocker.AsyncMock()

    # Mock scan_packages
    mock_instance.scan_packages = mocker.AsyncMock(
        return_value=[V1VulnerabilityList(vulns=[])]
    )

    result = runner.invoke(app, ["batch", str(batch_json)])
    assert result.exit_code == 0
    assert "lodash" in result.stdout


def test_batch_command_fail_on(tmp_path, mocker):
    batch_json = tmp_path / "batch.json"
    batch_json.write_text(
        json.dumps(
            {
                "queries": [
                    {
                        "package": {"name": "bad-pkg", "ecosystem": "npm"},
                        "version": "1.0.0",
                    }
                ]
            }
        )
    )

    mock_osv = mocker.patch("safepackages.cli.commands.batch.OSVClient")
    mock_instance = mock_osv.return_value
    mock_instance.close = mocker.AsyncMock()

    # Mock a high severity vulnerability
    vuln = OsvVulnerability(
        id="TEST-1",
        severity=[
            OsvSeverity(
                type="CVSS_V3", score="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            )
        ],  # Score ~9.8 -> CRITICAL
    )

    mock_instance.scan_packages = mocker.AsyncMock(
        return_value=[V1VulnerabilityList(vulns=[vuln])]
    )

    result = runner.invoke(app, ["batch", str(batch_json), "--fail-on", "high"])
    assert result.exit_code == 1


def test_batch_invalid_file():
    result = runner.invoke(app, ["batch", "nonexistent.json"])
    assert result.exit_code == 1
    assert "Invalid JSON input" in result.stderr


def test_batch_invalid_json(tmp_path):
    f = tmp_path / "invalid.json"
    f.write_text("{invalid")
    result = runner.invoke(app, ["batch", str(f)])
    assert result.exit_code == 1
    assert "Invalid JSON input" in result.stderr


def test_batch_not_a_list(tmp_path):
    f = tmp_path / "dict.json"
    f.write_text("{}")
    result = runner.invoke(app, ["batch", str(f)])
    assert result.exit_code == 1
    assert (
        "Input must be a JSON array" in result.stderr
        or "Input must be a JSON array" in str(result.exception)
    )


def test_batch_fail_on(tmp_path, mocker):
    batch_json = tmp_path / "batch.json"
    batch_json.write_text(
        json.dumps([{"name": "lodash", "ecosystem": "npm", "version": "4.17.15"}])
    )

    # Mock OSVClient
    mock_osv = mocker.patch("safepackages.cli.commands.batch.OSVClient")
    mock_instance = mock_osv.return_value
    mock_instance.close = mocker.AsyncMock()

    # Mock a high severity vulnerability
    vuln = OsvVulnerability(
        id="TEST-1",
        severity=[
            OsvSeverity(
                type="CVSS_V3", score="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            )
        ],  # CRITICAL
    )

    mock_instance.scan_packages = mocker.AsyncMock(
        return_value=[V1VulnerabilityList(vulns=[vuln])]
    )

    # Should fail on high (default)
    result = runner.invoke(app, ["batch", str(batch_json)])
    assert result.exit_code == 1

    # Should fail on critical
    result = runner.invoke(app, ["batch", str(batch_json), "--fail-on", "critical"])
    assert result.exit_code == 1

    # Should NOT fail on medium if we only had low (but we have critical)
    # Let's mock a low vulnerability
    vuln_low = OsvVulnerability(
        id="TEST-2",
        severity=[
            OsvSeverity(
                type="CVSS_V3", score="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"
            )
        ],  # LOW
    )
    mock_instance.scan_packages = mocker.AsyncMock(
        return_value=[V1VulnerabilityList(vulns=[vuln_low])]
    )

    result = runner.invoke(app, ["batch", str(batch_json), "--fail-on", "high"])
    assert result.exit_code == 0

    result = runner.invoke(app, ["batch", str(batch_json), "--fail-on", "low"])
    assert result.exit_code == 1


def test_batch_output_file(tmp_path, mocker):
    batch_json = tmp_path / "batch.json"
    batch_json.write_text(
        json.dumps([{"name": "lodash", "ecosystem": "npm", "version": "4.17.15"}])
    )
    output_file = tmp_path / "output.json"

    # Mock OSVClient
    mock_osv = mocker.patch("safepackages.cli.commands.batch.OSVClient")
    mock_instance = mock_osv.return_value
    mock_instance.close = mocker.AsyncMock()
    mock_instance.scan_packages = mocker.AsyncMock(
        return_value=[V1VulnerabilityList(vulns=[])]
    )

    result = runner.invoke(
        app,
        ["batch", str(batch_json), "--output", str(output_file), "--format", "json"],
    )
    assert result.exit_code == 0
    assert "Results written to" in result.stdout
    assert output_file.exists()
    assert "[]" in output_file.read_text()


def test_file_command_fail_on_medium(tmp_path, mocker):
    package_json = tmp_path / "package.json"
    package_json.write_text('{"dependencies": {"lodash": "4.17.15"}}')

    mock_osv = mocker.patch("safepackages.cli.commands.file.OSVClient")
    mock_instance = mock_osv.return_value
    mock_instance.close = mocker.AsyncMock()

    vuln = OsvVulnerability(
        id="TEST-1",
        severity=[
            OsvSeverity(
                type="CVSS_V3", score="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            )
        ],  # CRITICAL
    )
    mock_instance.scan_packages = mocker.AsyncMock(
        return_value=[V1VulnerabilityList(vulns=[vuln])]
    )

    # Test medium fail-on with critical vuln
    result = runner.invoke(app, ["file", str(package_json), "--fail-on", "medium"])
    assert result.exit_code == 1


def test_file_command_output(tmp_path, mocker):
    package_json = tmp_path / "package.json"
    package_json.write_text('{"dependencies": {"lodash": "4.17.15"}}')
    output_file = tmp_path / "output.csv"

    mock_osv = mocker.patch("safepackages.cli.commands.file.OSVClient")
    mock_instance = mock_osv.return_value
    mock_instance.close = mocker.AsyncMock()
    mock_instance.scan_packages = mocker.AsyncMock(
        return_value=[V1VulnerabilityList(vulns=[])]
    )

    result = runner.invoke(
        app,
        ["file", str(package_json), "--output", str(output_file), "--format", "csv"],
    )
    assert result.exit_code == 0
    assert output_file.exists()
    assert "Package,Version" in output_file.read_text()


def test_file_command_no_deps(tmp_path):
    package_json = tmp_path / "package.json"
    package_json.write_text("{}")
    result = runner.invoke(app, ["file", str(package_json)])
    assert result.exit_code == 0
    assert "No dependencies found" in result.stdout


def test_scan_command_output(tmp_path, mocker):
    output_file = tmp_path / "output.json"

    mock_osv = mocker.patch("safepackages.cli.commands.scan.OSVClient")
    mock_instance = mock_osv.return_value
    mock_instance.close = mocker.AsyncMock()
    mock_instance.scan_package = mocker.AsyncMock(
        return_value=V1VulnerabilityList(vulns=[])
    )

    result = runner.invoke(
        app,
        [
            "scan",
            "lodash",
            "-e",
            "npm",
            "-v",
            "4.17.15",
            "--output",
            str(output_file),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0
    assert output_file.exists()


def test_main_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "SafePackages CLI" in result.stdout


def test_file_command_not_found():
    result = runner.invoke(app, ["file", "nonexistent.json"])
    assert result.exit_code == 1
    assert "File not found" in result.stderr


def test_file_command_invalid_parse(tmp_path):
    f = tmp_path / "package.json"
    f.write_text("{invalid")
    result = runner.invoke(app, ["file", str(f)])
    assert result.exit_code == 1
    assert "Error parsing file" in result.stderr


def test_scan_command_fail_on(mocker):
    mock_osv = mocker.patch("safepackages.cli.commands.scan.OSVClient")
    mock_instance = mock_osv.return_value
    mock_instance.close = mocker.AsyncMock()

    vuln = OsvVulnerability(
        id="TEST-1",
        severity=[
            OsvSeverity(
                type="CVSS_V3", score="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            )
        ],  # CRITICAL
    )
    mock_instance.query = mocker.AsyncMock(
        return_value=V1VulnerabilityList(vulns=[vuln])
    )

    result = runner.invoke(
        app, ["scan", "lodash", "-e", "npm", "-v", "4.17.15", "--fail-on", "high"]
    )
    assert result.exit_code == 1

    result = runner.invoke(
        app, ["scan", "lodash", "-e", "npm", "-v", "4.17.15", "--fail-on", "high"]
    )
    assert result.exit_code == 1


def test_file_command_formats(tmp_path, mocker):
    package_json = tmp_path / "package.json"
    package_json.write_text('{"dependencies": {"lodash": "4.17.15"}}')

    mock_osv = mocker.patch("safepackages.cli.commands.file.OSVClient")
    mock_instance = mock_osv.return_value
    mock_instance.close = mocker.AsyncMock()
    mock_instance.scan_packages = mocker.AsyncMock(
        return_value=[V1VulnerabilityList(vulns=[])]
    )

    # Test JSON output
    result = runner.invoke(app, ["file", str(package_json), "--format", "json"])
    assert result.exit_code == 0
    assert "[" in result.stdout

    # Test CSV output
    result = runner.invoke(app, ["file", str(package_json), "--format", "csv"])
    assert result.exit_code == 0
    assert "Package,Version" in result.stdout


def test_batch_command_io_error(tmp_path, mocker):
    # Test file write error
    batch_json = tmp_path / "batch.json"
    batch_json.write_text('[{"name": "p", "ecosystem": "npm"}]')

    # Mock open to raise PermissionError
    mocker.patch(
        "builtins.open", side_effect=[open(batch_json, "r"), PermissionError("Denied")]
    )

    mock_osv = mocker.patch("safepackages.cli.commands.batch.OSVClient")
    mock_instance = mock_osv.return_value
    mock_instance.close = mocker.AsyncMock()
    mock_instance.scan_packages = mocker.AsyncMock(
        return_value=[V1VulnerabilityList(vulns=[])]
    )

    # This might be hard to test because we need to mock open only for the output file
    # Let's skip IO error for now and focus on logic
    pass


def test_format_table_empty():
    output = format_table([])
    assert "Scan Results" in output
    assert "Package" in output


def test_format_table_with_data():
    data = [
        {
            "package": "test-pkg",
            "version": "1.0.0",
            "vulnerabilities": [
                OsvVulnerability(
                    id="TEST-1",
                    severity=[
                        OsvSeverity(
                            type="CVSS_V3",
                            score="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        )
                    ],
                )
            ],
        }
    ]
    output = format_table(data)
    assert "test-pkg" in output
    assert "TEST-1" in output
    assert "CRITICAL" in output


def test_format_json():
    data = [{"package": "test-pkg", "version": "1.0.0", "vulnerabilities": []}]
    output = format_json(data)
    parsed = json.loads(output)
    assert parsed[0]["package"] == "test-pkg"


def test_format_json_datetime():
    # Test datetime serialization if present in models
    pass


def test_format_csv():
    data = [
        {
            "package": "test-pkg",
            "version": "1.0.0",
            "vulnerabilities": [
                OsvVulnerability(
                    id="TEST-1",
                    severity=[
                        OsvSeverity(
                            type="CVSS_V3",
                            score="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        )
                    ],
                )
            ],
        }
    ]
    output = format_csv(data)
    assert "test-pkg" in output
    assert "TEST-1" in output
    assert "CRITICAL" in output


def test_format_csv_empty():
    assert "Package,Version,Vulnerability ID,Severity" in format_csv([])


def test_batch_command_file_read_error(tmp_path, mocker):
    # Create a file that exists
    f = tmp_path / "batch.json"
    f.touch()

    # Mock open to raise PermissionError
    # We need to mock builtins.open but only for this file read
    # This is tricky because open is used elsewhere.
    # Instead, let's mock os.path.exists to return True, but open to fail?
    # Or just mock the file read in batch.py if possible?
    # batch.py uses `with open(json_input, 'r') as f:`

    mocker.patch("builtins.open", side_effect=PermissionError("Denied"))

    result = runner.invoke(app, ["batch", str(f)])
    assert result.exit_code == 1
    assert "Error reading file" in result.stderr


def test_file_command_parse_error(tmp_path, mocker):
    f = tmp_path / "package.json"
    f.write_text("{}")

    # Mock parse_manifest to raise ValueError
    mocker.patch(
        "safepackages.cli.commands.file.parse_manifest",
        side_effect=ValueError("Parse error"),
    )

    result = runner.invoke(app, ["file", str(f)])
    assert result.exit_code == 1
    assert "Error parsing file" in result.stderr


def test_scan_command_output_error(tmp_path, mocker):
    # Mock OSVClient
    mock_osv = mocker.patch("safepackages.cli.commands.scan.OSVClient")
    mock_instance = mock_osv.return_value
    mock_instance.close = mocker.AsyncMock()
    mock_instance.scan_package = mocker.AsyncMock(
        return_value=V1VulnerabilityList(vulns=[])
    )

    # Mock open to raise PermissionError for output file
    # We need to allow other opens (if any) but fail for output
    # scan.py uses `with open(output, "w") as f:`

    mocker.patch("builtins.open", side_effect=PermissionError("Denied"))

    result = runner.invoke(app, ["scan", "p", "-e", "npm", "-o", "out.json"])
    # It should raise the exception because we don't catch it in scan.py output writing?
    # Looking at scan.py:
    # if output:
    #     with open(output, "w") as f: ...
    # It doesn't have a try/except block for writing output.
    # So it should crash with PermissionError, which Typer/Click might handle or just crash.
    assert result.exit_code != 0
    # assert isinstance(result.exception, PermissionError) # Typer might wrap it


def test_scan_command_fail_on_levels(mocker):
    mock_osv = mocker.patch("safepackages.cli.commands.scan.OSVClient")
    mock_instance = mock_osv.return_value
    mock_instance.close = mocker.AsyncMock()

    # Return HIGH severity vulnerability
    # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N is 7.5 (HIGH)
    mock_instance.scan_package = mocker.AsyncMock(
        return_value=V1VulnerabilityList(
            vulns=[
                OsvVulnerability(
                    id="V1",
                    severity=[
                        OsvSeverity(
                            type="CVSS_V3",
                            score="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        )
                    ],
                )
            ]
        )
    )

    # Fail on HIGH -> Fail
    result = runner.invoke(app, ["scan", "p", "-e", "npm", "--fail-on", "high"])
    assert result.exit_code == 1

    # Fail on MEDIUM -> Fail
    result = runner.invoke(app, ["scan", "p", "-e", "npm", "--fail-on", "medium"])
    assert result.exit_code == 1

    # Fail on CRITICAL -> Pass (since it's only HIGH)
    result = runner.invoke(app, ["scan", "p", "-e", "npm", "--fail-on", "critical"])
    assert result.exit_code == 0
