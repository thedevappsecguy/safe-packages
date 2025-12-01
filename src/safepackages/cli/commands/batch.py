import typer
import asyncio
import json
import os
from typing import Optional
from ...core.client import OSVClient
from ..output import format_table, format_json, format_csv
from ..utils import check_fail_on


def scan_batch(
    json_input: str = typer.Argument(
        ..., help="JSON array of packages to scan or path to JSON file"
    ),
    format: str = typer.Option(
        "table", "--format", "-f", help="Output format: table, json, csv"
    ),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output to file"),
    fail_on: str = typer.Option(
        "high", "--fail-on", help="Exit with error if vulnerabilities found"
    ),
):
    """
    Batch scan packages from JSON input or file.
    Input format: '[{"name":"pkg","ecosystem":"npm","version":"1.0.0"},...]'
    Or path to a JSON file containing the array.
    """
    # Check if input is a file path
    if os.path.exists(json_input):
        try:
            with open(json_input, "r", encoding="utf-8") as f:
                json_input = f.read()
        except Exception as e:
            typer.echo(f"Error reading file: {e}", err=True)
            raise typer.Exit(code=1)

    try:
        packages = json.loads(json_input)
        if not isinstance(packages, list):
            raise ValueError("Input must be a JSON array")
    except json.JSONDecodeError:
        typer.echo("Invalid JSON input", err=True)
        raise typer.Exit(code=1)

    async def execute():
        client = OSVClient()
        try:
            vuln_lists = await client.scan_packages(packages)

            results = []
            for i, pkg in enumerate(packages):
                vulns = vuln_lists[i].vulns or []
                results.append(
                    {
                        "package": pkg.get("name", "unknown"),
                        "version": pkg.get("version", "unknown"),
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

    asyncio.run(execute())
