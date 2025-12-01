import typer
import asyncio
from typing import Optional
from ...core.client import OSVClient
from ...core.models import OsvPackage
from ..output import format_table, format_json, format_csv
from ..utils import check_fail_on


def scan_package(
    name: str = typer.Argument(..., help="Package name"),
    ecosystem: str = typer.Option(
        ..., "--ecosystem", "-e", help="Package ecosystem (npm, PyPI, etc.)"
    ),
    version: Optional[str] = typer.Option(
        None, "--version", "-v", help="Package version"
    ),
    format: str = typer.Option(
        "table", "--format", "-f", help="Output format: table, json, csv"
    ),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output to file"),
    fail_on: str = typer.Option(
        "high",
        "--fail-on",
        help="Exit with error if vulnerabilities found (default: high)",
    ),
):
    """
    Scan a single package for vulnerabilities.
    """

    async def run():
        client = OSVClient()
        try:
            pkg = OsvPackage(name=name, ecosystem=ecosystem)
            result = await client.scan_package(pkg, version)

            results = [
                {
                    "package": name,
                    "version": version,
                    "vulnerabilities": result.vulns or [],
                }
            ]

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
            if result.vulns:
                check_fail_on(result.vulns, fail_on)

        finally:
            await client.close()

    asyncio.run(run())
