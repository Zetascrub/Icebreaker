"""
NASLAnalyzer — matches discovered services against imported Nessus plugins.

At initialization it loads all enabled remote/combined NessusPlugin records from
the database and builds in-memory indexes keyed by port and service name.
During a scan, run() is called per-service and returns Finding objects for any
plugins whose criteria are satisfied by the service's port, banner, or detected
software version.

Matching strategy (in order):
  1. Port/service filter  — required_ports / required_services
  2. Banner regex         — banner_patterns tested against svc.meta["banner"]
  3. Version constraints  — version_constraints compared against svc.meta["version"]
  4. CPE match            — cpe_list intersected with svc.meta["cpe"]

A plugin fires a finding only if at least one of steps 2–4 produces a positive
match AND the plugin passed step 1.  Plugins with no matching criteria in steps
2–4 are skipped (they need a full NASL interpreter to be meaningful).
"""
from __future__ import annotations

import json
import re
import sqlite3
import uuid
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from packaging.version import Version, InvalidVersion

from icebreaker.core.models import Finding, RunContext, Service

# Plugin types this analyzer handles
_REMOTE_TYPES = {"remote", "combined"}

# Map severity strings → Finding severity
_SEV_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFO",
    "NONE": "INFO",
}

# Maximum findings per service (avoid flooding)
_MAX_FINDINGS_PER_SERVICE = 50


class _NessusPluginRecord:
    """Lightweight in-memory representation of a NessusPlugin row."""

    __slots__ = (
        "nessus_id", "name", "family", "severity", "description",
        "solution", "synopsis", "cve_ids", "cwe_id", "see_also",
        "cvss3_base_score", "cvss_base_score",
        "required_ports", "required_services", "required_keys",
        "cpe_list", "banner_patterns", "version_constraints",
        "_compiled_patterns",
    )

    def __init__(self, row: sqlite3.Row):
        self.nessus_id: int = row["nessus_id"]
        self.name: str = row["name"]
        self.family: Optional[str] = row["family"]
        self.severity: str = row["severity"] or "INFO"
        self.description: Optional[str] = row["description"]
        self.solution: Optional[str] = row["solution"]
        self.synopsis: Optional[str] = row["synopsis"]
        self.cvss3_base_score: Optional[float] = row["cvss3_base_score"]
        self.cvss_base_score: Optional[float] = row["cvss_base_score"]

        self.cve_ids: List[str] = _json_list(row["cve_ids"])
        self.cwe_id: Optional[str] = row["cwe_id"]
        self.see_also: List[str] = _json_list(row["see_also"])
        self.required_ports: List[int] = _json_list(row["required_ports"])
        self.required_services: List[str] = _json_list(row["required_services"])
        self.required_keys: List[str] = _json_list(row["required_keys"])
        self.cpe_list: List[str] = _json_list(row["cpe_list"])
        self.banner_patterns: List[Dict[str, str]] = _json_list(row["banner_patterns"])
        self.version_constraints: List[Dict[str, str]] = _json_list(row["version_constraints"])
        self._compiled_patterns: Optional[List[Optional[re.Pattern]]] = None

    def compiled_patterns(self) -> List[Optional[re.Pattern]]:
        if self._compiled_patterns is None:
            result = []
            for bp in self.banner_patterns:
                try:
                    flags = re.IGNORECASE if "i" in bp.get("flags", "") else 0
                    result.append(re.compile(bp["pattern"], flags))
                except re.error:
                    result.append(None)
            self._compiled_patterns = result
        return self._compiled_patterns


def _json_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, list) else []
    except Exception:
        return []


class NASLAnalyzer:
    """
    Analyzer that matches services against imported Nessus plugins.

    Plug into the Orchestrator alongside the other analyzers.  Works best
    after banner grabbing has populated svc.meta["banner"].
    """

    id = "nasl_plugins"
    # No `consumes` filter — we want to check every discovered service

    def __init__(self, db_path: str):
        """
        Load all enabled remote/combined plugins from the database.

        Args:
            db_path: Path to the icebreaker SQLite database.
        """
        self._plugins: List[_NessusPluginRecord] = []
        # port → list of plugin indices
        self._port_index: Dict[int, List[int]] = defaultdict(list)
        # service name → list of plugin indices
        self._service_index: Dict[str, List[int]] = defaultdict(list)
        # plugins with no port/service constraint (checked against every service)
        self._unconstrained: List[int] = []

        self._load(db_path)

    # ------------------------------------------------------------------ #
    # Analyzer protocol                                                    #
    # ------------------------------------------------------------------ #

    async def run(self, ctx: RunContext, service: Service) -> List[Finding]:
        if not self._plugins:
            return []

        candidates = self._candidates_for(service)
        if not candidates:
            return []

        # "banner" is the canonical key; fall back to "server" (HTTP Server header)
        # so that existing services stored before this fix still get matched
        banner = str(
            service.meta.get("banner") or service.meta.get("server") or ""
        )
        version = str(service.meta.get("version", "") or "")
        cpe_set = set(service.meta.get("cpe", []) or [])
        # Also derive a simple CPE vendor/product from service name for fuzzy matching
        svc_name_lower = (service.name or "").lower()

        # When nmap wasn't run with -sV (e.g. web-UI scans using TCPProbe), the
        # service has no CPE data.  Synthesise a CPE from the banner string so
        # that NASL plugins can still match by CPE even without nmap version data.
        if not cpe_set and banner:
            synthesised = _cpe_from_banner(banner)
            if synthesised:
                cpe_set = {synthesised}
                # Also extract the version if we don't have one yet
                if not version:
                    version = _version_from_banner(banner)

        # Detect Ubuntu/Debian backported packages.  These distros backport security
        # fixes without bumping the upstream version number, so version-based CVE
        # matching always produces false positives.  Nessus detects this and suppresses
        # CVE plugins for the affected service (plugin 39520 "Backported Security Patch
        # Detection").  We do the same: if the banner contains a distro marker we skip
        # version-scoped CVE findings and only emit INFO-level detection plugins.
        backported = _is_backported_package(banner)

        findings: List[Finding] = []

        # Emit a "Backported Security Patch Detection" info finding (mirrors Nessus
        # plugin 39520) when we suppress version-based CVEs due to distro backporting.
        if backported and banner:
            findings.append(Finding(
                id=f"nasl.backport.{service.target}.{service.port}",
                title="Backported Security Patch Detection (WWW)",
                severity="INFO",
                target=service.target,
                port=service.port,
                tags=["nessus", "web_server", "backport"],
                description=(
                    f"The remote web server banner ({banner[:120]}) indicates the service is "
                    "running a package maintained by a Linux distribution that backports security "
                    "fixes without changing the upstream version number. Version-based CVE checks "
                    "are suppressed for this service to avoid false positives."
                ),
                recommendation=(
                    "Use the distribution's package manager (e.g. apt, yum) or the vendor's "
                    "security advisories to determine whether specific CVEs are patched."
                ),
            ))

        for plugin in candidates:
            if len(findings) >= _MAX_FINDINGS_PER_SERVICE:
                break

            matched, match_type = self._check_plugin(
                plugin, banner, version, cpe_set, svc_name_lower,
                skip_version_cves=backported,
            )
            if matched:
                findings.append(self._make_finding(plugin, service, match_type))

        return findings

    # ------------------------------------------------------------------ #
    # Private — loading                                                    #
    # ------------------------------------------------------------------ #

    def _load(self, db_path: str) -> None:
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT nessus_id, name, family, severity,
                       description, solution, synopsis,
                       cvss_base_score, cvss3_base_score,
                       cve_ids, cwe_id, see_also,
                       required_ports, required_services, required_keys,
                       cpe_list, banner_patterns, version_constraints
                FROM nessus_plugins
                WHERE enabled = 1
                  AND plugin_type IN ('remote', 'combined')
                ORDER BY nessus_id
                """
            ).fetchall()
            conn.close()
        except Exception:
            return

        for i, row in enumerate(rows):
            try:
                rec = _NessusPluginRecord(row)
                self._plugins.append(rec)

                # Only index plugins that have at least one matching criterion
                has_criteria = (
                    rec.banner_patterns or rec.version_constraints or rec.cpe_list
                )
                if not has_criteria:
                    continue

                indexed = False
                for port in rec.required_ports:
                    self._port_index[port].append(i)
                    indexed = True
                for svc in rec.required_services:
                    self._service_index[svc.lower()].append(i)
                    indexed = True
                if not indexed:
                    self._unconstrained.append(i)
            except Exception:
                continue

    # ------------------------------------------------------------------ #
    # Private — matching                                                   #
    # ------------------------------------------------------------------ #

    def _candidates_for(self, service: Service) -> List[_NessusPluginRecord]:
        """Return deduplicated plugin records that might apply to this service."""
        seen: set = set()
        result: List[_NessusPluginRecord] = []

        def add(idx: int) -> None:
            if idx not in seen:
                seen.add(idx)
                result.append(self._plugins[idx])

        # Port-based candidates
        for idx in self._port_index.get(service.port, []):
            add(idx)

        # Service-name based candidates
        svc_lower = (service.name or "").lower()
        for idx in self._service_index.get(svc_lower, []):
            add(idx)

        # Unconstrained plugins always run (they have matching criteria but no port filter)
        for idx in self._unconstrained:
            add(idx)

        return result

    def _has_software_identity(
        self,
        plugin: _NessusPluginRecord,
        banner: str,
        cpe_set: set,
        svc_name_lower: str,
    ) -> bool:
        """
        Return True when we have positive evidence the service is running the
        software targeted by this plugin — required to gate version-only matches.

        Checks (any one suffices):
          • Service CPE set intersects the plugin's CPE list (prefix match)
          • Any CPE vendor or product token (≥4 chars) from the plugin appears
            in the banner text  — e.g. "apache" in "Apache/2.4.50"
          • Service name matches a *specific* required_service (not generic HTTP
            service names like "http"/"https"/"www" which cover too many products)
        """
        # CPE intersection (strongest signal)
        if cpe_set and plugin.cpe_list:
            for pc in plugin.cpe_list:
                for sc in cpe_set:
                    if sc.startswith(pc) or pc.startswith(sc):
                        return True

        # Extract the *product* token from plugin CPEs and look for it in the banner.
        # We deliberately skip the *vendor* token because it is often too broad —
        # "apache" matches both httpd and Tomcat banners, "microsoft" matches IIS and
        # many other products.  Using only the product (e.g. "nginx", "openssh",
        # "tomcat") avoids cross-product false positives.
        #
        # CPE URI structure: "cpe:/a:vendor:product:version" or "x-cpe:/a:vendor:product"
        # After split(":"): [scheme, "/a", vendor, product, ...]
        #                      [0]    [1]    [2]     [3]
        if banner and plugin.cpe_list:
            banner_lower = banner.lower()
            for cpe in plugin.cpe_list:
                raw_parts = cpe.split(":")
                # raw_parts[3] is the product field (if present)
                if len(raw_parts) >= 4:
                    product = raw_parts[3].strip("/").lower().replace("_", " ")
                    if product and len(product) >= 4 and product in banner_lower:
                        return True

        # Service names like "http", "ftp", "smtp", "ssh" are protocol names, not
        # product names — many different products serve each protocol, so matching
        # them would confirm identity for any plugin that targets that protocol
        # regardless of which software is actually running.  Identity via service
        # name is therefore not used; only CPE intersection and product-in-banner
        # are considered reliable enough signals.

        return False

    def _check_plugin(
        self,
        plugin: _NessusPluginRecord,
        banner: str,
        version: str,
        cpe_set: set,
        svc_name_lower: str,
        skip_version_cves: bool = False,
    ) -> Tuple[bool, str]:
        """
        Test one plugin against service data.
        Returns (matched: bool, match_type: str).

        Matching rules
        ──────────────
        • Banner regex  — pattern must be "specific" (≥4 consecutive word chars in
                          the pattern literal) to filter out catch-all expressions
                          like ``[0-9]+`` or ``^[^#].*``.
        • Version       — only fires when _has_software_identity() confirms the
                          service is plausibly running the plugin's target software.
        • CPE           — exact/prefix intersection; inherently identity-confirmed.
        • Fuzzy CPE     — CPE product in service name + specific banner match.
        """
        # 1. Banner regex check — skip catch-all patterns and short/ambiguous matches.
        #    Two guards are applied:
        #      a) _is_specific_pattern: the pattern literal must contain ≥4 consecutive
        #         word chars — filters ``[0-9]+``, ``^[^#].*``, etc.
        #      b) match length ≥ 4: the actual matched substring must be at least 4
        #         characters — filters 2-char alternation hits like "CH" matching the
        #         "ch" in "Apache", or 3-char version fragments like "0.5".
        if banner and plugin.banner_patterns:
            for bp, pat in zip(plugin.banner_patterns, plugin.compiled_patterns()):
                if pat and _is_specific_pattern(bp.get("pattern", "")):
                    m = pat.search(banner)
                    if m and len(m.group(0)) >= 4:
                        return True, "banner"

        # 2. Version constraint check — requires software identity confirmation.
        #    Skipped for Ubuntu/Debian backported packages (version string is frozen
        #    at the distro's base version even after security backports are applied).
        if version and plugin.version_constraints and not skip_version_cves:
            if self._has_software_identity(plugin, banner, cpe_set, svc_name_lower):
                if _version_in_constraints(version, plugin.version_constraints):
                    return True, "version"

        # 3. CPE match (exact prefix)
        #
        # Two sub-cases:
        #   a) Plugin has version_constraints: only fire if the detected version is
        #      in the vulnerable range AND the package is not backport-patched.
        #   b) Plugin has no version_constraints: it is a generic "software present"
        #      detection check.  Fire only when the plugin severity is INFO so we
        #      emit inventory/detection findings without flooding with unconfirmed
        #      vulnerabilities (e.g. a year-2000 Apache bug is not applicable to
        #      Apache 2.4.58 just because the CPE prefix matches).
        if cpe_set and plugin.cpe_list:
            for plugin_cpe in plugin.cpe_list:
                for svc_cpe in cpe_set:
                    if svc_cpe.startswith(plugin_cpe) or plugin_cpe.startswith(svc_cpe):
                        if plugin.version_constraints:
                            # Version-scoped check — skip for backported packages
                            if not skip_version_cves and version and _version_in_constraints(version, plugin.version_constraints):
                                return True, "cpe+version"
                        elif plugin.severity.upper() in ("INFO", "NONE"):
                            # Detection/inventory plugin — always safe to report
                            return True, "cpe"

        # 4. Fuzzy CPE-to-service-name: check if any CPE product name appears in the
        #    service name (e.g. plugin CPE "cpe:/a:apache:httpd" → "httpd" in "http")
        if svc_name_lower and plugin.cpe_list and banner:
            for cpe in plugin.cpe_list:
                parts = cpe.strip("/").split(":")
                if len(parts) >= 4:
                    product = parts[3].lower()
                    if product and len(product) > 3 and product in svc_name_lower:
                        # Only fire if there's also a specific banner pattern that matches
                        if plugin.banner_patterns:
                            for bp, pat in zip(plugin.banner_patterns, plugin.compiled_patterns()):
                                if pat and _is_specific_pattern(bp.get("pattern", "")):
                                    m = pat.search(banner)
                                    if m and len(m.group(0)) >= 4:
                                        return True, "banner+cpe"

        return False, ""

    # ------------------------------------------------------------------ #
    # Private — finding construction                                       #
    # ------------------------------------------------------------------ #

    def _make_finding(
        self,
        plugin: _NessusPluginRecord,
        service: Service,
        match_type: str,
    ) -> Finding:
        severity = _SEV_MAP.get(plugin.severity.upper(), "INFO")

        # Build references list: CVE links first, then see_also
        refs: List[str] = []
        for cve in plugin.cve_ids[:5]:
            refs.append(f"https://nvd.nist.gov/vuln/detail/{cve}")
        refs.extend(plugin.see_also[:3])

        # Build tags
        tags = ["nessus"]
        if plugin.family:
            tags.append(plugin.family.lower().replace(" ", "_"))
        if plugin.cve_ids:
            tags.extend(plugin.cve_ids[:3])
        tags.append(f"match:{match_type}")

        # CVSS score → risk_score
        cvss = plugin.cvss3_base_score or plugin.cvss_base_score
        risk_score = min(float(cvss), 10.0) if cvss else None

        description = plugin.description or plugin.synopsis or ""

        return Finding(
            id=f"nasl.{plugin.nessus_id}.{service.target}.{service.port}",
            title=plugin.name,
            severity=severity,
            target=service.target,
            port=service.port,
            tags=tags,
            description=description[:2000] if description else None,
            recommendation=plugin.solution,
            references=refs[:8],
            confidence=0.8 if match_type in ("banner", "version") else 0.6,
            risk_score=risk_score,
            details={
                "nessus_id": plugin.nessus_id,
                "family": plugin.family,
                "match_type": match_type,
                "cve_ids": plugin.cve_ids,
                "cwe_id": plugin.cwe_id,
                "cvss3_base_score": plugin.cvss3_base_score,
                "cvss_base_score": plugin.cvss_base_score,
            },
        )

    # ------------------------------------------------------------------ #
    # Convenience                                                          #
    # ------------------------------------------------------------------ #

    def plugin_count(self) -> int:
        return len(self._plugins)

    def indexed_count(self) -> int:
        return (
            sum(len(v) for v in self._port_index.values())
            + sum(len(v) for v in self._service_index.values())
            + len(self._unconstrained)
        )


# --------------------------------------------------------------------------- #
# Banner-to-CPE synthesis                                                      #
# --------------------------------------------------------------------------- #

# Map banner product tokens to (vendor, product) CPE tuples — mirrors the table
# in nmap_probe.py so banner-based scans get the same CPE coverage as nmap -sV.
_BANNER_TO_CPE: list[tuple[re.Pattern, tuple[str, str]]] = [
    (re.compile(r"Apache[/ ](\d[\d.]+)",               re.I),    ("apache",  "http_server")),
    (re.compile(r"Apache Tomcat[/ ](\d[\d.]+)",        re.I),    ("apache",  "tomcat")),
    (re.compile(r"nginx[/ ](\d[\d.]+)",                re.I),    ("nginx",   "nginx")),
    (re.compile(r"OpenSSH[_/ ](\d[\d.]+\w*)",          re.I),    ("openbsd", "openssh")),
    (re.compile(r"Microsoft-IIS[/ ](\d[\d.]+)",        re.I),    ("microsoft", "internet_information_server")),
    (re.compile(r"lighttpd[/ ](\d[\d.]+)",             re.I),    ("lighttpd", "lighttpd")),
    (re.compile(r"vsftpd[ /](\d[\d.]+)",               re.I),    ("vsftpd_project", "vsftpd")),
    (re.compile(r"ProFTPD[ /](\d[\d.]+)",              re.I),    ("proftpd", "proftpd")),
    (re.compile(r"Postfix[ /](\d[\d.]+)",              re.I),    ("postfix", "postfix")),
    (re.compile(r"MySQL[ /](\d[\d.]+)",                re.I),    ("oracle",  "mysql")),
    (re.compile(r"MariaDB[ /](\d[\d.]+)",              re.I),    ("mariadb", "mariadb")),
]


def _cpe_from_banner(banner: str) -> Optional[str]:
    """Return a synthesised CPE URI from *banner*, or None if unrecognised."""
    for pat, (vendor, product) in _BANNER_TO_CPE:
        m = pat.search(banner)
        if m:
            ver = m.group(1) if m.lastindex and m.group(1) else ""
            if ver:
                return f"cpe:/a:{vendor}:{product}:{ver}"
            return f"cpe:/a:{vendor}:{product}"
    return None


def _version_from_banner(banner: str) -> str:
    """Extract a bare version string from a banner like 'Apache/2.4.58 …'."""
    for pat, _ in _BANNER_TO_CPE:
        m = pat.search(banner)
        if m and m.lastindex and m.group(1):
            return m.group(1)
    return ""


# --------------------------------------------------------------------------- #
# Backport detection helper                                                    #
# --------------------------------------------------------------------------- #

# Patterns that indicate a package version string is from a distro that
# backports security fixes (Ubuntu, Debian, Red Hat/CentOS, SUSE).
# When present in a banner the reported upstream version number does NOT
# accurately reflect the installed patch level, so version-based CVE matching
# will produce false positives — exactly as Nessus plugin 39520 warns.
_BACKPORT_DISTRO_RE = re.compile(
    r"\b(Ubuntu|Debian|Raspbian|Red\s?Hat|CentOS|Fedora|RHEL|SUSE|openSUSE|AlmaLinux|Rocky)\b",
    re.IGNORECASE,
)


def _is_backported_package(banner: str) -> bool:
    """
    Return True when the banner string contains a distro marker that indicates
    the software version is managed by a distro that backports security fixes.
    In that case upstream version-based CVE checks are unreliable.
    """
    if not banner:
        return False
    return bool(_BACKPORT_DISTRO_RE.search(banner))


# --------------------------------------------------------------------------- #
# Pattern specificity helper                                                   #
# --------------------------------------------------------------------------- #

# Compiled once at import time
_SPECIFIC_PATTERN_RE = re.compile(r'\w{4,}')


def _is_specific_pattern(pattern: str) -> bool:
    """
    Return True if *pattern* is specific enough to be worth matching against a
    banner string.  Two classes of pattern are rejected as catch-alls:

    1. Patterns with an *empty alternative* — e.g. ``^general|`` has a trailing
       ``|`` creating an empty branch that matches the empty string at every
       position, so the regex matches any input unconditionally.
    2. Patterns with no run of four or more consecutive word characters in the
       literal text — e.g. ``[0-9]+``, ``^[^#].*``, ``^[a-zA-Z0-9]``.  These
       would match any alphanumeric content.

    Legitimate patterns like ``Apache``, ``WEBC_``, ``OpenSSH``, ``httpd``,
    ``nginx`` pass both checks.
    """
    # Reject empty alternatives (pattern starts/ends with | or has ||)
    stripped = pattern.strip()
    if stripped.startswith("|") or stripped.endswith("|") or "||" in stripped:
        return False
    return bool(_SPECIFIC_PATTERN_RE.search(pattern))


# --------------------------------------------------------------------------- #
# Version comparison helpers                                                   #
# --------------------------------------------------------------------------- #

def _parse_ver(v: str) -> Optional[Version]:
    """Parse a version string, returning None if unparseable."""
    try:
        return Version(v.strip())
    except (InvalidVersion, TypeError, ValueError):
        # Try stripping non-numeric suffixes
        cleaned = re.sub(r"[^0-9.].*$", "", v.strip())
        try:
            return Version(cleaned) if cleaned else None
        except (InvalidVersion, ValueError):
            return None


def _version_in_constraints(detected: str, constraints: List[Dict[str, str]]) -> bool:
    """
    Return True if `detected` version falls within any vulnerable constraint range.

    A constraint dict may have:
      min_version   — lower bound (inclusive)
      max_version   — upper bound (inclusive, i.e. last vulnerable version)
      fixed_version — first fixed version (exclusive upper bound if max_version absent)
      equal_or_less — single vulnerable version upper bound
    """
    dv = _parse_ver(detected)
    if dv is None:
        return False

    for c in constraints:
        try:
            min_v = _parse_ver(c["min_version"]) if "min_version" in c else None
            max_v = _parse_ver(c["max_version"]) if "max_version" in c else None
            fixed_v = _parse_ver(c["fixed_version"]) if "fixed_version" in c else None
            equal_v = _parse_ver(c["equal_or_less"]) if "equal_or_less" in c else None

            # Lower bound check
            if min_v and dv < min_v:
                continue

            # Upper bound — prefer max_version (inclusive), fall back to fixed_version (exclusive)
            if max_v:
                if dv <= max_v:
                    return True
            elif fixed_v:
                if dv < fixed_v:
                    return True
            elif equal_v:
                if dv <= equal_v:
                    return True
            elif min_v:
                # Only a lower bound — any version >= min is considered affected
                return True
        except Exception:
            continue

    return False
