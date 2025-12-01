import typer
import asyncio
import os
from typing import Optional
from ...core.client import OSVClient
from ...core.parsers import parse_manifest
from ..output import format_table, format_json, format_csv
from ..utils import check_fail_on


def scan_file(
    file_path: str = typer.Argument(..., help="Path to manifest file"),
    format: str = typer.Option(
        "table", "--format", "-f", help="Output format: table, json, csv"
    ),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output to file"),
    fail_on: str = typer.Option(
        "high",
        "--fail-on",
        help="Exit with error if vulnerabilities found (default: high)",
    ),
    include_dev: bool = typer.Option(
        False, "--include-dev", help="Include dev dependencies"
    ),
):
    """
    Scan a manifest file for vulnerabilities.
    """
    if not os.path.exists(file_path):
        typer.echo(f"File not found: {file_path}", err=True)
        raise typer.Exit(code=1)

    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    try:
        parse_result = parse_manifest(file_path, content)
    except ValueError as e:
        typer.echo(f"Error parsing file: {e}", err=True)
        raise typer.Exit(code=1)

    async def run():
        client = OSVClient()
        try:
            packages_to_scan = []
            for dep in parse_result.dependencies:
                if not include_dev and dep.is_dev:
                    continue
                packages_to_scan.append(
                    {
                        "name": dep.name,
                        "ecosystem": parse_result.ecosystem,
                        "version": dep.version,
                    }
                )

            if not packages_to_scan:
                typer.echo("No dependencies found to scan.")
                return

            # Batch scan or parallel scan
            # Using scan_packages from client which uses batch query
            vuln_lists = await client.scan_packages(packages_to_scan)

            results = []
            for i, pkg in enumerate(packages_to_scan):
                vulns = vuln_lists[i].vulns or []
                results.append(
                    {
                        "package": pkg["name"],
                        "version": pkg["version"],
                        "vulnerabilities": vulns,
                    }
                )

            output_text = ""
            if format == "table":
                output_text = format_table(results)
            elif format == "json":
                output_text = format_json(results)
            elif format == "csv":
                output_text = format_csv(results)

            if output:
                with open(output, "w", encoding="utf-8") as f:
                    f.write(output_text)
                typer.echo(f"Results written to {output}")
            else:
                typer.echo(output_text)

            # Fail-on logic
            all_vulns = []
            for res in results:
                all_vulns.extend(res.get("vulnerabilities", []))

            if all_vulns:
                check_fail_on(all_vulns, fail_on)

        finally:
            await client.close()

    asyncio.run(run())
