"""
AI client for generating executive summaries using various AI providers.

Supports:
- Ollama (local models)
- Anthropic Claude (API key required)
- OpenAI (API key required)
"""
from __future__ import annotations
import os
from typing import Optional, Dict, Any
from abc import ABC, abstractmethod
import httpx


class AIProvider(ABC):
    """Base class for AI providers."""

    @abstractmethod
    async def generate(self, prompt: str) -> str:
        """Generate a response from the AI model."""
        pass


class OllamaProvider(AIProvider):
    """Ollama provider for local LLM inference."""

    def __init__(self, model: str = "llama3.2", base_url: str = "http://localhost:11434"):
        self.model = model
        self.base_url = base_url

    async def generate(self, prompt: str) -> str:
        """Generate response using Ollama API."""
        async with httpx.AsyncClient(timeout=120.0) as client:
            try:
                response = await client.post(
                    f"{self.base_url}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "stream": False,
                    }
                )
                response.raise_for_status()
                return response.json()["response"]
            except httpx.HTTPError as e:
                raise RuntimeError(f"Ollama API error: {e}") from e


class AnthropicProvider(AIProvider):
    """Anthropic Claude provider."""

    def __init__(self, model: str = "claude-3-5-sonnet-20241022", api_key: Optional[str] = None):
        self.model = model
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable not set")

    async def generate(self, prompt: str) -> str:
        """Generate response using Anthropic API."""
        async with httpx.AsyncClient(timeout=120.0) as client:
            try:
                response = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": self.api_key,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json={
                        "model": self.model,
                        "max_tokens": 4096,
                        "messages": [
                            {"role": "user", "content": prompt}
                        ]
                    }
                )
                response.raise_for_status()
                return response.json()["content"][0]["text"]
            except httpx.HTTPError as e:
                raise RuntimeError(f"Anthropic API error: {e}") from e


class OpenAIProvider(AIProvider):
    """OpenAI provider."""

    def __init__(self, model: str = "gpt-4o-mini", api_key: Optional[str] = None):
        self.model = model
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY environment variable not set")

    async def generate(self, prompt: str) -> str:
        """Generate response using OpenAI API."""
        async with httpx.AsyncClient(timeout=120.0) as client:
            try:
                response = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.model,
                        "messages": [
                            {"role": "user", "content": prompt}
                        ],
                        "max_tokens": 4096,
                    }
                )
                response.raise_for_status()
                return response.json()["choices"][0]["message"]["content"]
            except httpx.HTTPError as e:
                raise RuntimeError(f"OpenAI API error: {e}") from e


class AIClient:
    """Main AI client that routes to appropriate provider."""

    PROVIDERS = {
        "ollama": OllamaProvider,
        "anthropic": AnthropicProvider,
        "claude": AnthropicProvider,  # alias
        "openai": OpenAIProvider,
    }

    def __init__(self, provider: str, model: Optional[str] = None, **kwargs):
        """
        Initialize AI client.

        Args:
            provider: Provider name (ollama, anthropic/claude, openai)
            model: Model name (provider-specific defaults if not specified)
            **kwargs: Additional provider-specific arguments
        """
        provider_lower = provider.lower()
        if provider_lower not in self.PROVIDERS:
            available = ", ".join(self.PROVIDERS.keys())
            raise ValueError(f"Unknown provider '{provider}'. Available: {available}")

        provider_class = self.PROVIDERS[provider_lower]

        # Initialize provider with model if specified
        init_kwargs: Dict[str, Any] = {}
        if model:
            init_kwargs["model"] = model
        init_kwargs.update(kwargs)

        self.provider = provider_class(**init_kwargs)

    async def generate_summary(self, prompt: str) -> str:
        """Generate AI summary."""
        return await self.provider.generate(prompt)
