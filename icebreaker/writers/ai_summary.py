"""
AI-powered executive summary writer.

Analyzes scan results and generates a comprehensive executive summary
using AI models (Ollama, Claude, OpenAI, etc.).
"""
from __future__ import annotations
from pathlib import Path
from typing import List, Optional
from icebreaker.core.models import RunContext, Service, Finding
from icebreaker.core.ai_client import AIClient


class AISummaryWriter:
    """Writer that generates AI-powered executive summaries."""

    id = "ai_summary"

    def __init__(self, ai_provider: str, ai_model: Optional[str] = None, base_url: Optional[str] = None):
        """
        Initialize AI summary writer.

        Args:
            ai_provider: AI provider name (ollama, anthropic, openai)
            ai_model: Model name (optional, uses provider defaults)
            base_url: Base URL for AI provider (optional, for remote endpoints)
        """
        self.ai_provider = ai_provider
        self.ai_model = ai_model
        self.base_url = base_url

        # Build kwargs for AIClient
        client_kwargs = {}
        if base_url:
            client_kwargs['base_url'] = base_url

        self.client = AIClient(provider=ai_provider, model=ai_model, **client_kwargs)

    def write(self, ctx: RunContext, services: List[Service], findings: List[Finding]) -> None:
        """Generate and write AI-powered executive summary."""
        # Build context for AI
        prompt = self._build_prompt(ctx, services, findings)

        # Generate summary using synchronous method
        try:
            summary = self.client.generate_summary_sync(prompt)
        except Exception as e:
            summary = f"Error generating AI summary: {e}"

        # Write to file
        out_path = Path(ctx.out_dir) / "ai_executive_summary.md"
        self._write_summary_file(out_path, ctx, summary)

    def _build_prompt(self, ctx: RunContext, services: List[Service], findings: List[Finding]) -> str:
        """Build prompt for AI model."""
        # Summarize services
        service_summary = self._summarize_services(services)

        # Summarize findings by severity
        findings_summary = self._summarize_findings(findings)

        prompt = f"""You are a cybersecurity expert analyzing the results of a security reconnaissance scan performed using Icebreaker.

Your task is to generate a comprehensive executive summary of the scan results that can be presented to both technical and non-technical stakeholders.

## Scan Information
- Run ID: {ctx.run_id}
- Preset: {ctx.preset}
- Total Services Discovered: {len(services)}
- Total Findings: {len(findings)}

## Services Discovered
{service_summary}

## Security Findings
{findings_summary}

## Instructions
Generate an executive summary that includes:

1. **Overview**: Brief high-level summary (2-3 sentences) of what was scanned and the overall security posture

2. **Key Findings**: Highlight the most critical security issues discovered, focusing on:
   - Critical and high severity findings
   - Patterns or trends across multiple systems
   - Services that may be vulnerable or misconfigured

3. **Risk Assessment**: Evaluate the overall risk level (Critical, High, Medium, Low) based on:
   - Number and severity of findings
   - Types of services exposed
   - Potential attack vectors

4. **Recommendations**: Provide prioritized, actionable recommendations for:
   - Immediate actions (critical issues)
   - Short-term improvements (high/medium issues)
   - Long-term security posture improvements

5. **Technical Details**: Brief technical context for each major finding, suitable for security teams

Keep the summary concise but comprehensive (aim for 400-600 words). Use clear, professional language suitable for executive audiences while maintaining technical accuracy for security teams.

Format the response in Markdown with appropriate headers and sections."""

        return prompt

    def _summarize_services(self, services: List[Service]) -> str:
        """Create a textual summary of discovered services."""
        if not services:
            return "No services discovered."

        # Group by target
        by_target = {}
        for s in services:
            by_target.setdefault(s.target, []).append(s)

        lines = []
        for target in sorted(by_target.keys()):
            target_services = sorted(by_target[target], key=lambda x: x.port)
            ports = [f"{s.port}/{s.name or 'unknown'}" for s in target_services]
            lines.append(f"- {target}: {', '.join(ports)}")

        return "\n".join(lines)

    def _summarize_findings(self, findings: List[Finding]) -> str:
        """Create a textual summary of findings grouped by severity."""
        if not findings:
            return "No security findings detected."

        # Group by severity
        by_severity = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
            "INFO": []
        }

        for f in findings:
            sev = f.severity.upper()
            if sev in by_severity:
                by_severity[sev].append(f)
            else:
                by_severity.setdefault("INFO", []).append(f)

        lines = []
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            items = by_severity.get(severity, [])
            if not items:
                continue

            lines.append(f"\n### {severity} ({len(items)})")
            for finding in items:
                port_info = f":{finding.port}" if finding.port else ""
                details_preview = ""
                if finding.details:
                    # Show first few key details
                    detail_items = [f"{k}={v}" for k, v in list(finding.details.items())[:3]]
                    if detail_items:
                        details_preview = f" ({', '.join(detail_items)})"

                rec = f"\n  Recommendation: {finding.recommendation}" if finding.recommendation else ""
                lines.append(f"- **{finding.title}** on {finding.target}{port_info}{details_preview}{rec}")

        return "\n".join(lines)

    def _write_summary_file(self, path: Path, ctx: RunContext, summary: str) -> None:
        """Write the summary to a markdown file."""
        content = f"""# Icebreaker: AI Executive Summary

**Generated using**: {self.ai_provider} ({self.ai_model or 'default model'})
**Run ID**: {ctx.run_id}
**Scan Date**: {ctx.started_at.strftime('%Y-%m-%d %H:%M:%S UTC')}

---

{summary}

---

*This executive summary was automatically generated using AI analysis of the Icebreaker scan results. Please review the detailed reports (summary.md, findings.jsonl) for complete technical information.*
"""
        path.write_text(content, encoding="utf-8")
