from typing import List, Optional, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field
from datetime import datetime

try:
    from cvss import CVSS3, CVSS2
except ImportError:
    CVSS3 = None
    CVSS2 = None


class OsvCreditType(str, Enum):
    UNSPECIFIED = "UNSPECIFIED"
    OTHER = "OTHER"
    FINDER = "FINDER"
    REPORTER = "REPORTER"
    ANALYST = "ANALYST"
    COORDINATOR = "COORDINATOR"
    REMEDIATION_DEVELOPER = "REMEDIATION_DEVELOPER"
    REMEDIATION_REVIEWER = "REMEDIATION_REVIEWER"
    REMEDIATION_VERIFIER = "REMEDIATION_VERIFIER"
    TOOL = "TOOL"
    SPONSOR = "SPONSOR"


class OsvRangeType(str, Enum):
    UNSPECIFIED = "UNSPECIFIED"
    GIT = "GIT"
    SEMVER = "SEMVER"
    ECOSYSTEM = "ECOSYSTEM"


class OsvReferenceType(str, Enum):
    NONE = "NONE"
    WEB = "WEB"
    ADVISORY = "ADVISORY"
    REPORT = "REPORT"
    FIX = "FIX"
    PACKAGE = "PACKAGE"
    ARTICLE = "ARTICLE"
    EVIDENCE = "EVIDENCE"


class OsvSeverityType(str, Enum):
    UNSPECIFIED = "UNSPECIFIED"
    CVSS_V4 = "CVSS_V4"
    CVSS_V3 = "CVSS_V3"
    CVSS_V2 = "CVSS_V2"


class OsvPackage(BaseModel):
    name: str = Field(..., description="Name of the package")
    ecosystem: str = Field(..., description="The ecosystem for this package")
    purl: Optional[str] = Field(None, description="The package URL for this package")


class OsvEvent(BaseModel):
    introduced: Optional[str] = None
    fixed: Optional[str] = None
    limit: Optional[str] = None
    lastAffected: Optional[str] = None


class OsvRange(BaseModel):
    type: OsvRangeType
    repo: Optional[str] = None
    events: List[OsvEvent]


class OsvSeverity(BaseModel):
    type: OsvSeverityType
    score: str


class OsvCredit(BaseModel):
    name: Optional[str] = None
    contact: Optional[List[str]] = None
    type: Optional[OsvCreditType] = None


class OsvReference(BaseModel):
    type: OsvReferenceType
    url: str


class OsvAffected(BaseModel):
    package: OsvPackage
    ranges: Optional[List[OsvRange]] = None
    versions: Optional[List[str]] = None
    ecosystemSpecific: Optional[Dict[str, Any]] = None
    databaseSpecific: Optional[Dict[str, Any]] = None
    severity: Optional[List[OsvSeverity]] = None


class OsvVulnerability(BaseModel):
    schemaVersion: Optional[str] = None
    id: Optional[str] = None
    published: Optional[datetime] = None
    modified: Optional[datetime] = None
    withdrawn: Optional[datetime] = None
    aliases: Optional[List[str]] = None
    related: Optional[List[str]] = None
    summary: Optional[str] = None
    details: Optional[str] = None
    affected: Optional[List[OsvAffected]] = None
    references: Optional[List[OsvReference]] = None
    databaseSpecific: Optional[Dict[str, Any]] = None
    severity: Optional[List[OsvSeverity]] = None
    credits: Optional[List[OsvCredit]] = None

    @property
    def severity_level(self) -> str:
        """
        Calculate severity level (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN)
        based on CVSS score.
        """
        score = 0.0

        # Check database specific severity first
        if self.databaseSpecific and "severity" in self.databaseSpecific:
            return self.databaseSpecific["severity"]

        # Check affected packages
        if self.affected:
            for affected in self.affected:
                if (
                    affected.databaseSpecific
                    and "severity" in affected.databaseSpecific
                ):
                    return affected.databaseSpecific["severity"]

                if affected.severity:
                    for sev in affected.severity:
                        try:
                            # Try to parse as vector string first using cvss library
                            from cvss import CVSS3, CVSS2

                            if "CVSS:3" in sev.score:
                                c = CVSS3(sev.score)
                                s = c.scores()[0]  # Base score
                                if s > score:
                                    score = s
                            elif "CVSS:4" in sev.score:
                                # CVSS v4 parsing (simple regex for now as cvss lib might not support it)
                                import re

                                # Look for /VC:H/VI:H/VA:H etc or just parse the score if available elsewhere?
                                # Actually, OSV API returns vector string in 'score' field for V4 too.
                                # But there is no standard python lib for V4 yet commonly available.
                                # Wait, the OSV schema says 'score' is quantitative score?
                                # But debug output showed: "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N"
                                # So it is a vector.
                                # We can't easily calculate score from vector without a full implementation.
                                # However, often the API might provide a numeric score in databaseSpecific?
                                # In this case databaseSpecific was null.
                                # Let's try to find a way.
                                # Actually, for now, let's map the vector to a rough severity if we can't calculate?
                                # Or better, just regex for the score if it was pre-calculated? No it's not.
                                # Wait, if we can't calculate, we can't give a score.
                                # BUT, looking at the debug output for GHSA-4249-gjr8-jpq3, the severity is 8.7 (High).
                                # Is there any other field? No.
                                # We MUST implement a basic V4 calculator or find a library?
                                # Or maybe we can just rely on the fact that we can't calculate it easily and return UNKNOWN?
                                # NO, user wants it fixed.
                                # Let's look at the vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N
                                # VC:H (High Confidentiality), VI:H (High Integrity), VA:L (Low Availability).
                                # This is clearly High/Critical.
                                # Since we can't easily calculate, let's check if we can use a library.
                                # The project has `cvss` dependency. Does `cvss` support v4?
                                # Let's check if `cvss` library has CVSS4 class.
                                try:
                                    from cvss import CVSS4

                                    c = CVSS4(sev.score)
                                    s = c.base_score
                                    if s > score:
                                        score = s
                                except (ImportError, AttributeError):
                                    # Fallback: simple heuristic for CVSS v4
                                    # Check for High impact in Confidentiality, Integrity, or Availability
                                    # VC:H, VI:H, VA:H
                                    if (
                                        "VC:H" in sev.score
                                        or "VI:H" in sev.score
                                        or "VA:H" in sev.score
                                    ):
                                        s = 9.0  # Treat as CRITICAL/HIGH
                                        if s > score:
                                            score = s
                                    elif (
                                        "VC:L" in sev.score
                                        or "VI:L" in sev.score
                                        or "VA:L" in sev.score
                                    ):
                                        s = 5.0  # Treat as MEDIUM
                                        if s > score:
                                            score = s

                            elif (
                                "CVSS:2" in sev.score
                                or "/AV:" in sev.score
                                or sev.score.startswith("AV:")
                            ):
                                score_str = sev.score
                                if score_str.startswith("CVSS:2.0/"):
                                    score_str = score_str.replace("CVSS:2.0/", "")

                                if CVSS2:
                                    c = CVSS2(score_str)
                                    s = c.scores()[0]
                                    if s > score:
                                        score = s
                                else:
                                    # Fallback if cvss library not available
                                    import re

                                    match = re.search(r"(\d+(\.\d+)?)", score_str)
                                    if match:
                                        s = float(match.group(1))
                                        if s > score:
                                            score = s
                            else:
                                # Fallback to simple number parsing
                                import re

                                match = re.search(r"(\d+(\.\d+)?)", sev.score)
                                if match:
                                    s = float(match.group(1))
                                    if s > score:
                                        score = s
                        except Exception:
                            pass

        # Check top level severity
        if self.severity:
            for sev in self.severity:
                try:
                    # Try to parse as vector string first using cvss library
                    from cvss import CVSS3, CVSS2

                    if "CVSS:3" in sev.score:
                        c = CVSS3(sev.score)
                        s = c.scores()[0]  # Base score
                        if s > score:
                            score = s
                    elif "CVSS:4" in sev.score:
                        try:
                            from cvss import CVSS4

                            c = CVSS4(sev.score)
                            s = c.base_score
                            if s > score:
                                score = s
                        except (ImportError, AttributeError):
                            # Fallback: simple heuristic for CVSS v4
                            if (
                                "VC:H" in sev.score
                                or "VI:H" in sev.score
                                or "VA:H" in sev.score
                            ):
                                s = 9.0
                                if s > score:
                                    score = s
                            elif (
                                "VC:L" in sev.score
                                or "VI:L" in sev.score
                                or "VA:L" in sev.score
                            ):
                                s = 5.0
                                if s > score:
                                    score = s
                    elif (
                        "CVSS:2" in sev.score
                        or "/AV:" in sev.score
                        or sev.score.startswith("AV:")
                    ):
                        score_str = sev.score
                        if score_str.startswith("CVSS:2.0/"):
                            score_str = score_str.replace("CVSS:2.0/", "")

                            if CVSS2:
                                c = CVSS2(score_str)
                                s = c.scores()[0]
                                if s > score:
                                    score = s
                            else:
                                # Fallback if cvss library not available
                                import re

                                match = re.search(r"(\d+(\.\d+)?)", score_str)
                                if match:
                                    s = float(match.group(1))
                                    if s > score:
                                        score = s
                    else:
                        # Fallback to simple number parsing
                        import re

                        match = re.search(r"(\d+(\.\d+)?)", sev.score)
                        if match:
                            s = float(match.group(1))
                            if s > score:
                                score = s
                except Exception:
                    pass

        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0.0:
            return "LOW"

        return "UNKNOWN"


class V1Query(BaseModel):
    commit: Optional[str] = None
    version: Optional[str] = None
    package: Optional[OsvPackage] = None
    pageToken: Optional[str] = None


class V1BatchQuery(BaseModel):
    queries: List[V1Query]


class V1VulnerabilityList(BaseModel):
    vulns: Optional[List[OsvVulnerability]] = None
    nextPageToken: Optional[str] = None


class V1BatchVulnerabilityList(BaseModel):
    results: List[V1VulnerabilityList]


class PackageScanResult(BaseModel):
    package: OsvPackage
    vulnerabilities: List[OsvVulnerability]
    scannedAt: Optional[datetime] = None
    hasVulnerabilities: bool
    criticalCount: int
    highCount: int
    mediumCount: int
    lowCount: int
    malwareCount: int


class BatchScanResult(BaseModel):
    packages: List[PackageScanResult]
    totalPackages: int
    totalVulnerabilities: int
    criticalCount: int
    highCount: int
    mediumCount: int
    lowCount: int
    malwareCount: int
    scannedAt: Optional[datetime] = None


class ParsedDependency(BaseModel):
    name: str
    version: str
    is_dev: bool = False
    source: Optional[str] = None


class ManifestParseResult(BaseModel):
    ecosystem: str
    dependencies: List[ParsedDependency]
    manifest_file: str
