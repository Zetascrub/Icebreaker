"""
NASL (Nessus Attack Scripting Language) parser.

Extracts vulnerability metadata AND matching criteria from .nasl files:
  - Core metadata: title, description, CVE, CVSS, solution, family
  - Port/service requirements: script_require_ports(), script_require_keys()
  - CPE strings: script_set_attribute(attribute:"cpe", ...)
  - Banner patterns: egrep()/ereg() calls in the check body
  - Version constraints: vcf::check_version_and_report() constraint blocks
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional


# Maps NASL ACT_* constants to human-readable categories
CATEGORY_MAP = {
    "ACT_INIT": "init",
    "ACT_SCANNER": "scanner",
    "ACT_SETTINGS": "settings",
    "ACT_GATHER_INFO": "gather_info",
    "ACT_MIXED_ATTACK": "mixed_attack",
    "ACT_ATTACK": "attack",
    "ACT_DENIAL": "denial",
    "ACT_DESTRUCTIVE_ATTACK": "destructive",
    "ACT_KILL_HOST": "kill_host",
    "ACT_FLOOD": "flood",
    "ACT_END": "end",
}

# Maps service KB key names to short service names
SERVICE_KEY_MAP = {
    "Services/ftp": "ftp",
    "Services/http": "http",
    "Services/https": "https",
    "Services/smtp": "smtp",
    "Services/imap": "imap",
    "Services/pop3": "pop3",
    "Services/ssh": "ssh",
    "Services/telnet": "telnet",
    "Services/rdp": "rdp",
    "Services/vnc": "vnc",
    "Services/mysql": "mysql",
    "Services/mssql": "mssql",
    "Services/ldap": "ldap",
    "Services/snmp": "snmp",
    "Services/dns": "dns",
    "Services/nntp": "nntp",
    "Services/finger": "finger",
    "Services/www": "http",
}

SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "none": "INFO",
    "info": "INFO",
}


class NASLParser:
    """Parser for NASL plugin files."""

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def parse_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Parse a .nasl file and return metadata dict, or None on failure."""
        try:
            content = Path(file_path).read_text(encoding="utf-8", errors="ignore")
            return self.parse_content(content, Path(file_path).stem)
        except Exception:
            return None

    def parse_content(self, content: str, plugin_id: str) -> Optional[Dict[str, Any]]:
        """Parse NASL source text and return a metadata dict."""
        try:
            # Split at exit(0) to get description block vs check body
            parts = re.split(r'\bexit\s*\(\s*0\s*\)\s*;', content, maxsplit=1)
            desc_block = parts[0]
            check_body = parts[1] if len(parts) > 1 else ""

            metadata = {
                # Identity
                "plugin_id": plugin_id,
                "nessus_id": self._extract_script_id(desc_block),
                "plugin_type": self._extract_plugin_type(desc_block),
                "category": self._extract_category(desc_block),
                # Descriptive
                "title": self._extract_name(desc_block),
                "description": self._extract_description(desc_block),
                "solution": self._extract_solution(desc_block),
                "synopsis": self._extract_synopsis(desc_block),
                "family": self._extract_family(desc_block),
                # Severity / scoring
                "risk_factor": self._extract_risk_factor(desc_block),
                "cvss_base_score": self._extract_cvss_score(desc_block),
                "cvss_vector": self._extract_cvss_vector(desc_block),
                "cvss3_base_score": self._extract_cvss3_score(desc_block),
                "cvss3_vector": self._extract_cvss3_vector(desc_block),
                # References
                "cve": self._extract_cve(desc_block),
                "cwe": self._extract_cwe(desc_block),
                "see_also": self._extract_see_also(desc_block),
                # Dates
                "plugin_publication_date": self._extract_plugin_publication_date(desc_block),
                "plugin_modification_date": self._extract_plugin_modification_date(desc_block),
                # Matching criteria (new)
                "cpe_list": self._extract_cpe_list(desc_block),
                "required_ports": self._extract_required_ports(desc_block),
                "required_services": self._extract_required_services(desc_block),
                "required_keys": self._extract_required_keys(desc_block),
                "banner_patterns": self._extract_banner_patterns(check_body),
                "version_constraints": self._extract_version_constraints(check_body),
            }

            return metadata if metadata["title"] else None

        except Exception:
            return None

    def to_nessus_plugin_dict(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Convert parse_content() output to a NessusPlugin-compatible dict."""
        risk = metadata.get("risk_factor", "MEDIUM").upper()
        severity = SEVERITY_MAP.get(risk.lower(), "MEDIUM")

        cvss_score = metadata.get("cvss3_base_score") or metadata.get("cvss_base_score")
        cvss_vector = metadata.get("cvss3_vector") or metadata.get("cvss_vector")

        description = metadata.get("description", "")
        synopsis = metadata.get("synopsis", "")
        if synopsis and not description:
            description = synopsis
        elif synopsis and synopsis not in description:
            description = f"{synopsis}\n\n{description}"

        nessus_id = metadata.get("nessus_id")
        if not nessus_id:
            return {}

        return {
            "nessus_id": nessus_id,
            "name": metadata.get("title", "Unknown"),
            "family": metadata.get("family"),
            "plugin_type": metadata.get("plugin_type"),
            "category": metadata.get("category"),
            "severity": severity,
            "cvss_base_score": metadata.get("cvss_base_score"),
            "cvss3_base_score": metadata.get("cvss3_base_score"),
            "cvss_vector": cvss_score and cvss_vector,   # only store if we have both
            "cvss3_vector": metadata.get("cvss3_vector"),
            "cve_ids": metadata.get("cve", []),
            "cwe_id": metadata.get("cwe"),
            "description": description or None,
            "solution": metadata.get("solution"),
            "synopsis": synopsis or None,
            "see_also": metadata.get("see_also", [])[:10],
            "cpe_list": metadata.get("cpe_list", []),
            "required_ports": metadata.get("required_ports", []),
            "required_services": metadata.get("required_services", []),
            "required_keys": metadata.get("required_keys", []),
            "banner_patterns": metadata.get("banner_patterns", []),
            "version_constraints": metadata.get("version_constraints", []),
            "plugin_publication_date": metadata.get("plugin_publication_date"),
            "plugin_modification_date": metadata.get("plugin_modification_date"),
            "enabled": True,
        }

    # Backward-compat shim used by old import code
    def to_finding_template(self, nasl_metadata: Dict[str, Any]) -> Dict[str, Any]:
        risk_factor = nasl_metadata.get("risk_factor", "MEDIUM").upper()
        severity = SEVERITY_MAP.get(risk_factor.lower(), "MEDIUM")
        cvss_score = nasl_metadata.get("cvss3_base_score") or nasl_metadata.get("cvss_base_score")
        cvss_vector = nasl_metadata.get("cvss3_vector") or nasl_metadata.get("cvss_vector")
        description = nasl_metadata.get("description", "")
        synopsis = nasl_metadata.get("synopsis", "")
        if synopsis and not description:
            description = synopsis
        elif synopsis and synopsis not in description:
            description = f"{synopsis}\n\n{description}"
        solution = nasl_metadata.get("solution", "No solution available.")
        impact = synopsis or description[:500] if description else "Impact information not available."
        references = list(nasl_metadata.get("see_also", []))
        for cve in nasl_metadata.get("cve", []):
            references.append(f"https://nvd.nist.gov/vuln/detail/{cve}")
        plugin_id = nasl_metadata.get("plugin_id", "unknown")
        return {
            "finding_id": f"NESSUS-{plugin_id}",
            "title": nasl_metadata.get("title", "Unknown Vulnerability"),
            "category": nasl_metadata.get("family", "General"),
            "description": description or "No description available.",
            "impact": impact,
            "remediation": solution,
            "severity": severity,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "cwe_id": nasl_metadata.get("cwe"),
            "references": references[:10],
            "enabled": True,
        }

    # ------------------------------------------------------------------ #
    # Identity / classification                                            #
    # ------------------------------------------------------------------ #

    def _extract_script_id(self, content: str) -> Optional[int]:
        match = re.search(r'\bscript_id\s*\(\s*(\d+)\s*\)', content)
        return int(match.group(1)) if match else None

    def _extract_plugin_type(self, content: str) -> Optional[str]:
        result = self._extract_attribute(content, "plugin_type")
        if result:
            return result.lower()
        return None

    def _extract_category(self, content: str) -> Optional[str]:
        match = re.search(r'\bscript_category\s*\(\s*(ACT_\w+)\s*\)', content)
        if match:
            act = match.group(1)
            return CATEGORY_MAP.get(act, act.lower().replace("act_", ""))
        return None

    def _extract_family(self, content: str) -> Optional[str]:
        result = self._extract_function_arg(content, "script_family", "english")
        if not result:
            result = self._extract_attribute(content, "plugin_family")
        return result

    # ------------------------------------------------------------------ #
    # Descriptive metadata                                                 #
    # ------------------------------------------------------------------ #

    def _extract_name(self, content: str) -> Optional[str]:
        result = self._extract_function_arg(content, "script_name", "english")
        if not result:
            result = self._extract_attribute(content, "plugin_name")
        return result

    def _extract_description(self, content: str) -> Optional[str]:
        result = self._extract_attribute(content, "description")
        if not result:
            result = self._extract_function_arg(content, "script_description", "english")
        return result

    def _extract_synopsis(self, content: str) -> Optional[str]:
        return self._extract_attribute(content, "synopsis")

    def _extract_solution(self, content: str) -> Optional[str]:
        return self._extract_attribute(content, "solution")

    def _extract_risk_factor(self, content: str) -> str:
        result = self._extract_attribute(content, "risk_factor")
        return result.upper() if result else "MEDIUM"

    def _extract_cvss_score(self, content: str) -> Optional[float]:
        return self._parse_float(self._extract_attribute(content, "cvss_base_score"))

    def _extract_cvss_vector(self, content: str) -> Optional[str]:
        # script_set_cvss_base_vector("CVSS2#AV:N/...")
        match = re.search(r'script_set_cvss_base_vector\s*\(\s*"([^"]+)"', content)
        if match:
            return match.group(1).replace("CVSS2#", "")
        return self._extract_attribute(content, "cvss_base_vector")

    def _extract_cvss3_score(self, content: str) -> Optional[float]:
        return self._parse_float(self._extract_attribute(content, "cvss3_base_score"))

    def _extract_cvss3_vector(self, content: str) -> Optional[str]:
        match = re.search(r'script_set_cvss3_base_vector\s*\(\s*"([^"]+)"', content)
        if match:
            return match.group(1).replace("CVSS:3.0/", "").replace("CVSS:3.1/", "")
        return self._extract_attribute(content, "cvss3_base_vector")

    def _extract_cve(self, content: str) -> List[str]:
        cves: List[str] = []
        # script_cve_id("CVE-2024-1234", "CVE-2024-5678")
        for match in re.finditer(r'script_cve_id\s*\(([^)]+)\)', content, re.IGNORECASE):
            for cve_id in re.findall(r'CVE-\d{4}-\d+', match.group(1), re.IGNORECASE):
                cves.append(cve_id.upper())
        return list(dict.fromkeys(cves))  # deduplicate, preserve order

    def _extract_cwe(self, content: str) -> Optional[str]:
        match = re.search(r'CWE-(\d+)', content, re.IGNORECASE)
        return f"CWE-{match.group(1)}" if match else None

    def _extract_see_also(self, content: str) -> List[str]:
        refs: List[str] = []
        for match in re.finditer(
            r'script_set_attribute\s*\(\s*attribute\s*:\s*"see_also"\s*,\s*value\s*:\s*"([^"]*)"',
            content, re.DOTALL | re.IGNORECASE
        ):
            for line in match.group(1).splitlines():
                line = line.strip()
                if line:
                    refs.append(line)
        return refs

    def _extract_plugin_publication_date(self, content: str) -> Optional[str]:
        return self._extract_attribute(content, "plugin_publication_date")

    def _extract_plugin_modification_date(self, content: str) -> Optional[str]:
        return self._extract_attribute(content, "plugin_modification_date")

    # ------------------------------------------------------------------ #
    # Matching criteria                                                    #
    # ------------------------------------------------------------------ #

    def _extract_cpe_list(self, content: str) -> List[str]:
        """Extract all CPE strings from script_set_attribute(attribute:"cpe", ...) calls."""
        cpes: List[str] = []
        for match in re.finditer(
            r'script_set_attribute\s*\(\s*attribute\s*:\s*"cpe"\s*,\s*value\s*:\s*"([^"]+)"',
            content, re.IGNORECASE
        ):
            cpe = match.group(1).strip()
            if cpe:
                cpes.append(cpe)
        return list(dict.fromkeys(cpes))

    def _extract_required_ports(self, content: str) -> List[int]:
        """Extract numeric port numbers from script_require_ports() calls."""
        ports: List[int] = []
        match = re.search(r'script_require_ports\s*\(([^)]+)\)', content, re.IGNORECASE | re.DOTALL)
        if match:
            for token in re.findall(r'\b(\d{1,5})\b', match.group(1)):
                port = int(token)
                if 1 <= port <= 65535:
                    ports.append(port)
        return list(dict.fromkeys(ports))

    def _extract_required_services(self, content: str) -> List[str]:
        """Extract service names from Services/X entries in script_require_ports()."""
        services: List[str] = []
        match = re.search(r'script_require_ports\s*\(([^)]+)\)', content, re.IGNORECASE | re.DOTALL)
        if match:
            for key in re.findall(r'"(Services/[^"]+)"', match.group(1)):
                svc = SERVICE_KEY_MAP.get(key, key.split("/")[-1].lower())
                services.append(svc)
        return list(dict.fromkeys(services))

    def _extract_required_keys(self, content: str) -> List[str]:
        """Extract KB keys from script_require_keys() — e.g. 'installed_sw/Apache'."""
        keys: List[str] = []
        match = re.search(r'script_require_keys\s*\(([^)]+)\)', content, re.IGNORECASE | re.DOTALL)
        if match:
            for key in re.findall(r'"([^"]+)"', match.group(1)):
                if key and "Services/" not in key:
                    keys.append(key)
        return list(dict.fromkeys(keys))

    def _extract_banner_patterns(self, check_body: str) -> List[Dict[str, str]]:
        """
        Extract regex patterns used for banner matching in the check body.

        Handles:
          egrep(pattern:"<regex>", string:<var>)
          ereg(pattern:"<regex>", string:<var>)
          if (banner =~ "<regex>")
        """
        patterns: List[Dict[str, str]] = []
        seen: set = set()

        # egrep / ereg calls
        for match in re.finditer(
            r'\b(?:egrep|ereg)\s*\(\s*(?:[^,]*,\s*)?pattern\s*:\s*"((?:[^"\\]|\\.)*)"',
            check_body, re.IGNORECASE
        ):
            p = match.group(1)
            if p and p not in seen and len(p) > 3:
                seen.add(p)
                patterns.append({"pattern": p, "flags": "i"})

        # Also catch pattern as first arg: egrep(pattern:"...", ...)
        for match in re.finditer(
            r'\b(?:egrep|ereg)\s*\(\s*pattern\s*:\s*"((?:[^"\\]|\\.)*)"',
            check_body, re.IGNORECASE
        ):
            p = match.group(1)
            if p and p not in seen and len(p) > 3:
                seen.add(p)
                patterns.append({"pattern": p, "flags": "i"})

        # banner =~ "regex" style
        for match in re.finditer(
            r'\b\w+\s*=~\s*"((?:[^"\\]|\\.)*)"',
            check_body
        ):
            p = match.group(1)
            if p and p not in seen and len(p) > 3:
                seen.add(p)
                patterns.append({"pattern": p, "flags": "i"})

        return patterns[:20]  # cap at 20 patterns per plugin

    def _extract_version_constraints(self, check_body: str) -> List[Dict[str, str]]:
        """
        Extract version range constraints from vcf::check_version_and_report() calls.

        Parses blocks like:
          { 'min_version' : '2.4.0', 'max_version' : '2.4.61', 'fixed_version' : '2.4.62' }
        """
        constraints: List[Dict[str, str]] = []

        # Match individual constraint blocks { 'key' : 'value', ... }
        block_re = re.compile(r'\{([^}]+)\}', re.DOTALL)
        kv_re = re.compile(r"['\"](\w+)['\"\s]*:\s*['\"]([^'\"]+)['\"]")

        for block_match in block_re.finditer(check_body):
            block = block_match.group(1)
            kv = {m.group(1): m.group(2) for m in kv_re.finditer(block)}

            # Only keep blocks that look like version constraints
            if any(k in kv for k in ("min_version", "max_version", "fixed_version", "equal_or_less")):
                entry: Dict[str, str] = {}
                for key in ("min_version", "max_version", "fixed_version", "equal_or_less", "fixed_display"):
                    if key in kv:
                        entry[key] = kv[key]
                if entry:
                    constraints.append(entry)

        return constraints[:50]  # cap at 50 constraints per plugin

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    def _extract_function_arg(self, content: str, function_name: str, arg_name: str) -> Optional[str]:
        pattern = rf'{function_name}\s*\([^)]*{arg_name}\s*:\s*["\']([^"\']*)["\']'
        match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
        return self._clean_text(match.group(1)) if match else None

    def _extract_attribute(self, content: str, attribute_name: str) -> Optional[str]:
        pattern = (
            rf'script_set_attribute\s*\(\s*attribute\s*:\s*["\']({re.escape(attribute_name)})["\']'
            rf'.*?value\s*:\s*["\']([^"\']*)["\']'
        )
        match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
        return self._clean_text(match.group(2)) if match else None

    def _clean_text(self, text: str) -> str:
        if not text:
            return ""
        text = re.sub(r'\s+', ' ', text)
        text = re.sub(r'\s*\+\s*', '', text)
        text = text.replace('\\n', '\n').replace('\\t', '\t').replace('\\"', '"').replace("\\'", "'")
        return text.strip()

    @staticmethod
    def _parse_float(value: Optional[str]) -> Optional[float]:
        if value is None:
            return None
        try:
            return float(value)
        except (ValueError, TypeError):
            return None
