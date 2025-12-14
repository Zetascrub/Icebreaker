"""
AI service for enhancing findings using LLMs (Ollama).
"""
import logging
import httpx
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session

from icebreaker.db.models import AIServiceConfig

logger = logging.getLogger(__name__)


class AIService:
    """Service for AI-powered finding enhancement."""

    def __init__(self, db: Session):
        """
        Initialize the AI service.

        Args:
            db: Database session
        """
        self.db = db
        self.config = self._get_ollama_config()

    def _get_ollama_config(self) -> Optional[AIServiceConfig]:
        """Get Ollama configuration from database."""
        config = self.db.query(AIServiceConfig).filter(
            AIServiceConfig.provider == "ollama",
            AIServiceConfig.enabled == True
        ).first()
        return config

    async def enhance_finding(
        self,
        title: str,
        description: str,
        severity: str,
        target: str,
        port: Optional[int] = None,
        raw_output: Optional[str] = None
    ) -> Dict[str, str]:
        """
        Enhance a finding using AI.

        Args:
            title: Finding title
            description: Current description
            severity: Severity level
            target: Target host/IP
            port: Target port
            raw_output: Raw scanner output

        Returns:
            Dictionary with enhanced fields:
            - description: Enhanced description
            - impact: Impact statement
            - recommendation: Detailed remediation steps
        """
        if not self.config:
            raise ValueError("Ollama is not configured or enabled")

        # Build the prompt
        prompt = self._build_enhancement_prompt(
            title=title,
            description=description,
            severity=severity,
            target=target,
            port=port,
            raw_output=raw_output
        )

        # Call Ollama API
        try:
            enhanced_text = await self._call_ollama(prompt)

            # Parse the response
            parsed = self._parse_enhancement_response(enhanced_text)

            return parsed

        except Exception as e:
            logger.error(f"Error enhancing finding: {str(e)}")
            raise

    def _build_enhancement_prompt(
        self,
        title: str,
        description: str,
        severity: str,
        target: str,
        port: Optional[int],
        raw_output: Optional[str]
    ) -> str:
        """Build the prompt for AI enhancement."""
        prompt = f"""You are a cybersecurity expert helping to document a security finding from a penetration test.

Finding Information:
- Title: {title}
- Severity: {severity}
- Target: {target}{f':{port}' if port else ''}
- Current Description: {description}
"""

        if raw_output:
            prompt += f"\n- Raw Scanner Output:\n{raw_output[:1000]}\n"

        prompt += """
Please provide an enhanced, professional finding description following this format:

## Description
[Provide a clear, professional description of the vulnerability or finding. Include technical details and context.]

## Impact
[Explain the potential business and technical impact if this vulnerability is exploited. Be specific about what an attacker could achieve.]

## Recommendation
[Provide detailed, actionable remediation steps. Include specific commands, configurations, or best practices where applicable.]

Keep the tone professional and technical. Focus on clarity and actionability.
"""

        return prompt

    async def _call_ollama(self, prompt: str) -> str:
        """
        Call Ollama API to generate text.

        Args:
            prompt: The prompt to send

        Returns:
            Generated text
        """
        base_url = self.config.base_url or "http://localhost:11434"
        model = self.config.model or "llama2"

        url = f"{base_url}/api/generate"

        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.7,
                "top_p": 0.9,
            }
        }

        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()

            data = response.json()
            return data.get("response", "")

    def _parse_enhancement_response(self, text: str) -> Dict[str, str]:
        """
        Parse the AI response into structured fields.

        Args:
            text: Raw AI response

        Returns:
            Dictionary with description, impact, and recommendation
        """
        result = {
            "description": "",
            "impact": "",
            "recommendation": ""
        }

        # Split by markdown headers
        sections = {
            "description": ["## Description", "## DESCRIPTION"],
            "impact": ["## Impact", "## IMPACT"],
            "recommendation": ["## Recommendation", "## RECOMMENDATION", "## Remediation", "## REMEDIATION"]
        }

        current_section = None
        current_content = []

        for line in text.split('\n'):
            line_stripped = line.strip()

            # Check if this line is a section header
            is_header = False
            for section_key, headers in sections.items():
                if line_stripped in headers:
                    # Save previous section
                    if current_section and current_content:
                        result[current_section] = '\n'.join(current_content).strip()

                    # Start new section
                    current_section = section_key
                    current_content = []
                    is_header = True
                    break

            if not is_header and current_section:
                current_content.append(line)

        # Save last section
        if current_section and current_content:
            result[current_section] = '\n'.join(current_content).strip()

        # Fallback: if parsing failed, put everything in description
        if not result["description"] and not result["impact"] and not result["recommendation"]:
            result["description"] = text.strip()

        return result


async def enhance_finding_with_ai(
    db: Session,
    title: str,
    description: str,
    severity: str,
    target: str,
    port: Optional[int] = None,
    raw_output: Optional[str] = None
) -> Dict[str, str]:
    """
    Standalone function to enhance a finding with AI.

    Args:
        db: Database session
        title: Finding title
        description: Current description
        severity: Severity level
        target: Target host/IP
        port: Target port
        raw_output: Raw scanner output

    Returns:
        Dictionary with enhanced fields
    """
    service = AIService(db)
    return await service.enhance_finding(
        title=title,
        description=description,
        severity=severity,
        target=target,
        port=port,
        raw_output=raw_output
    )
