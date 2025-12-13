"""
NASL (Nessus Attack Scripting Language) parser for importing Nessus plugins.

Extracts vulnerability metadata from .nasl files and converts to FindingTemplate format.
"""
import re
from typing import Dict, Any, Optional, List
from pathlib import Path


class NASLParser:
    """Parser for NASL plugin files."""

    def __init__(self):
        self.severity_map = {
            'critical': 'CRITICAL',
            'high': 'HIGH',
            'medium': 'MEDIUM',
            'low': 'LOW',
            'none': 'INFO',
            'info': 'INFO'
        }

    def parse_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        """
        Parse a NASL file and extract vulnerability metadata.

        Args:
            file_path: Path to the .nasl file

        Returns:
            Dictionary with extracted metadata or None if parsing fails
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            return self.parse_content(content, Path(file_path).stem)

        except Exception as e:
            print(f"Error parsing {file_path}: {e}")
            return None

    def parse_content(self, content: str, plugin_id: str) -> Optional[Dict[str, Any]]:
        """
        Parse NASL content string.

        Args:
            content: NASL file content
            plugin_id: Plugin identifier (usually filename without .nasl)

        Returns:
            Dictionary with extracted metadata
        """
        try:
            metadata = {
                'plugin_id': plugin_id,
                'title': self._extract_name(content),
                'description': self._extract_description(content),
                'solution': self._extract_solution(content),
                'synopsis': self._extract_synopsis(content),
                'risk_factor': self._extract_risk_factor(content),
                'cvss_base_score': self._extract_cvss_score(content),
                'cvss_vector': self._extract_cvss_vector(content),
                'cvss3_base_score': self._extract_cvss3_score(content),
                'cvss3_vector': self._extract_cvss3_vector(content),
                'cve': self._extract_cve(content),
                'cwe': self._extract_cwe(content),
                'see_also': self._extract_see_also(content),
                'plugin_publication_date': self._extract_plugin_publication_date(content),
                'plugin_modification_date': self._extract_plugin_modification_date(content),
                'family': self._extract_family(content),
            }

            # Only return if we have at least a title
            if metadata['title']:
                return metadata
            return None

        except Exception as e:
            print(f"Error parsing content for {plugin_id}: {e}")
            return None

    def _extract_function_arg(self, content: str, function_name: str, arg_name: str) -> Optional[str]:
        """Extract argument value from NASL function call."""
        # Match: function_name(arg_name:"value" or arg_name:'value')
        pattern = rf'{function_name}\s*\([^)]*{arg_name}\s*:\s*["\']([^"\']*)["\']'
        match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
        if match:
            return self._clean_text(match.group(1))
        return None

    def _extract_attribute(self, content: str, attribute_name: str) -> Optional[str]:
        """Extract script_set_attribute value."""
        # Match: script_set_attribute(attribute:"name", value:"value")
        pattern = rf'script_set_attribute\s*\(\s*attribute\s*:\s*["\']({attribute_name})["\'].*?value\s*:\s*["\']([^"\']*)["\']'
        match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
        if match:
            return self._clean_text(match.group(2))
        return None

    def _extract_name(self, content: str) -> Optional[str]:
        """Extract plugin name."""
        # Try script_name first
        result = self._extract_function_arg(content, 'script_name', 'english')
        if result:
            return result

        # Fallback to script_set_attribute
        return self._extract_attribute(content, 'plugin_name')

    def _extract_description(self, content: str) -> Optional[str]:
        """Extract description."""
        result = self._extract_attribute(content, 'description')
        if not result:
            result = self._extract_function_arg(content, 'script_description', 'english')
        return result

    def _extract_synopsis(self, content: str) -> Optional[str]:
        """Extract synopsis."""
        return self._extract_attribute(content, 'synopsis')

    def _extract_solution(self, content: str) -> Optional[str]:
        """Extract solution/remediation."""
        return self._extract_attribute(content, 'solution')

    def _extract_risk_factor(self, content: str) -> Optional[str]:
        """Extract risk factor."""
        result = self._extract_attribute(content, 'risk_factor')
        if result:
            return result.upper()
        return 'MEDIUM'  # Default

    def _extract_cvss_score(self, content: str) -> Optional[float]:
        """Extract CVSS v2 base score."""
        score_str = self._extract_attribute(content, 'cvss_base_score')
        if score_str:
            try:
                return float(score_str)
            except ValueError:
                pass
        return None

    def _extract_cvss_vector(self, content: str) -> Optional[str]:
        """Extract CVSS v2 vector."""
        return self._extract_attribute(content, 'cvss_base_vector')

    def _extract_cvss3_score(self, content: str) -> Optional[float]:
        """Extract CVSS v3 base score."""
        score_str = self._extract_attribute(content, 'cvss3_base_score')
        if score_str:
            try:
                return float(score_str)
            except ValueError:
                pass
        return None

    def _extract_cvss3_vector(self, content: str) -> Optional[str]:
        """Extract CVSS v3 vector."""
        return self._extract_attribute(content, 'cvss3_base_vector')

    def _extract_cve(self, content: str) -> List[str]:
        """Extract CVE IDs."""
        cves = []
        # Look for script_cve_id calls
        pattern = r'script_cve_id\s*\(\s*["\']([^"\']+)["\']'
        matches = re.finditer(pattern, content, re.IGNORECASE)
        for match in matches:
            cve_ids = match.group(1).split(',')
            for cve_id in cve_ids:
                cve_id = cve_id.strip().strip('"').strip("'")
                if cve_id and cve_id.startswith('CVE-'):
                    cves.append(cve_id)
        return cves

    def _extract_cwe(self, content: str) -> Optional[str]:
        """Extract CWE ID."""
        # Look for CWE mentions in various places
        pattern = r'CWE-(\d+)'
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            return f"CWE-{match.group(1)}"
        return None

    def _extract_see_also(self, content: str) -> List[str]:
        """Extract see_also references."""
        see_also = self._extract_attribute(content, 'see_also')
        if see_also:
            # Split by newlines and clean
            refs = [line.strip() for line in see_also.split('\n') if line.strip()]
            return refs
        return []

    def _extract_plugin_publication_date(self, content: str) -> Optional[str]:
        """Extract plugin publication date."""
        return self._extract_attribute(content, 'plugin_publication_date')

    def _extract_plugin_modification_date(self, content: str) -> Optional[str]:
        """Extract plugin modification date."""
        return self._extract_attribute(content, 'plugin_modification_date')

    def _extract_family(self, content: str) -> Optional[str]:
        """Extract plugin family/category."""
        result = self._extract_function_arg(content, 'script_family', 'english')
        if not result:
            result = self._extract_attribute(content, 'plugin_family')
        return result

    def _clean_text(self, text: str) -> str:
        """Clean extracted text."""
        if not text:
            return ""

        # Remove extra whitespace
        text = re.sub(r'\s+', ' ', text)

        # Remove NASL string concatenation
        text = re.sub(r'\s*\+\s*', '', text)

        # Decode common escape sequences
        text = text.replace('\\n', '\n')
        text = text.replace('\\t', '\t')
        text = text.replace('\\"', '"')
        text = text.replace("\\'", "'")

        return text.strip()

    def to_finding_template(self, nasl_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert NASL metadata to FindingTemplate format.

        Args:
            nasl_metadata: Parsed NASL metadata

        Returns:
            Dictionary suitable for creating FindingTemplate
        """
        # Determine severity
        risk_factor = nasl_metadata.get('risk_factor', 'MEDIUM').upper()
        severity = self.severity_map.get(risk_factor.lower(), 'MEDIUM')

        # Prefer CVSS v3 over v2
        cvss_score = nasl_metadata.get('cvss3_base_score') or nasl_metadata.get('cvss_base_score')
        cvss_vector = nasl_metadata.get('cvss3_vector') or nasl_metadata.get('cvss_vector')

        # Build description
        description = nasl_metadata.get('description', '')
        synopsis = nasl_metadata.get('synopsis', '')
        if synopsis and not description:
            description = synopsis
        elif synopsis and synopsis not in description:
            description = f"{synopsis}\n\n{description}"

        # Get solution (remediation)
        solution = nasl_metadata.get('solution', 'No solution available.')

        # Build impact from description or synopsis
        impact = synopsis or description[:500] if description else "Impact information not available."

        # Get references
        references = nasl_metadata.get('see_also', [])

        # Add CVE references
        cves = nasl_metadata.get('cve', [])
        for cve in cves:
            references.append(f"https://nvd.nist.gov/vuln/detail/{cve}")

        # Create finding_id from plugin_id
        plugin_id = nasl_metadata.get('plugin_id', 'unknown')
        finding_id = f"NESSUS-{plugin_id}"

        return {
            'finding_id': finding_id,
            'title': nasl_metadata.get('title', 'Unknown Vulnerability'),
            'category': nasl_metadata.get('family', 'General'),
            'description': description or 'No description available.',
            'impact': impact,
            'remediation': solution,
            'severity': severity,
            'cvss_score': cvss_score,
            'cvss_vector': cvss_vector,
            'cwe_id': nasl_metadata.get('cwe'),
            'references': references[:10],  # Limit to 10 references
            'enabled': True,
        }
