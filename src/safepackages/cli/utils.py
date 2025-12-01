import typer
from typing import List
from safepackages.core.models import OsvVulnerability


def check_fail_on(vulns: List[OsvVulnerability], fail_on: str) -> None:
    """
    Check if vulnerabilities meet the fail-on criteria and exit if they do.

    Args:
        vulns: List of vulnerabilities to check.
        fail_on: Severity level to fail on (low, medium, high, critical).

    Raises:
        typer.Exit: If the fail-on criteria are met.
    """
    if not vulns:
        return

    has_critical = any(v.severity_level == "CRITICAL" for v in vulns)
    has_high = any(v.severity_level == "HIGH" for v in vulns)
    has_medium = any(v.severity_level == "MEDIUM" for v in vulns)

    fail_level = fail_on.lower()

    should_fail = False
    if fail_level == "critical" and has_critical:
        should_fail = True
    elif fail_level == "high" and (has_critical or has_high):
        should_fail = True
    elif fail_level == "medium" and (has_critical or has_high or has_medium):
        should_fail = True
    elif fail_level == "low":  # Any vulnerability
        should_fail = True

    if should_fail:
        # We could print a message here, but the command usually prints results before calling this.
        # Maybe just exit with code 1.
        raise typer.Exit(code=1)
