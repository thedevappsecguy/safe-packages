import json
import csv
from typing import List, Any, Dict
from rich.console import Console
from rich.table import Table

console = Console()


def format_table(results: List[Dict[str, Any]]):
    """
    Format results as a rich table.
    results: List of dicts with keys: package, version, vulnerabilities (List[OsvVulnerability])
    """
    table = Table(title="Scan Results")
    table.add_column("Package", style="cyan")
    table.add_column("Version", style="magenta")
    table.add_column("Vulnerabilities", style="red")
    table.add_column("Severity", style="yellow")

    for result in results:
        pkg_name = result["package"]
        version = result["version"] or "N/A"
        vulns = result["vulnerabilities"]

        if not vulns:
            table.add_row(pkg_name, version, "None", "None")
        else:
            for vuln in vulns:
                vuln_id = vuln.id
                severity = vuln.severity_level

                table.add_row(pkg_name, version, vuln_id, severity)

    with console.capture() as capture:
        console.print(table)
    return capture.get()


def format_json(results: List[Dict[str, Any]]):
    """
    Format results as JSON.
    """
    # Convert Pydantic models to dicts
    serializable_results = []
    for result in results:
        res = result.copy()
        res["vulnerabilities"] = [
            v.model_dump(mode="json", exclude_none=True) for v in res["vulnerabilities"]
        ]
        serializable_results.append(res)

    return json.dumps(serializable_results, indent=2)


def format_csv(results: List[Dict[str, Any]]):
    """
    Format results as CSV.
    """
    import io

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Package", "Version", "Vulnerability ID", "Severity"])

    for result in results:
        pkg_name = result["package"]
        version = result["version"] or "N/A"
        vulns = result["vulnerabilities"]

        if not vulns:
            writer.writerow([pkg_name, version, "None", "None"])
        else:
            for vuln in vulns:
                vuln_id = vuln.id
                severity = vuln.severity_level

                writer.writerow([pkg_name, version, vuln_id, severity])

    return output.getvalue()
