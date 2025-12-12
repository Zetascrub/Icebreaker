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
import asyncio


class AIProvider(ABC):
    """Base class for AI providers."""

    @abstractmethod
    def generate_sync(self, prompt: str) -> str:
        """Generate a response from the AI model (synchronous)."""
        pass

    @abstractmethod
    async def generate(self, prompt: str) -> str:
        """Generate a response from the AI model (asynchronous)."""
        pass


class OllamaProvider(AIProvider):
    """Ollama provider for local LLM inference."""

    def __init__(self, model: str = "llama3.2", base_url: str = "http://localhost:11434"):
        self.model = model
        # Clean up base_url
        self.base_url = base_url.replace("http://", "").replace("https://", "")

    def generate_sync(self, prompt: str) -> str:
        """Generate response using Ollama API (synchronous)."""
        import json

        url = f"http://{self.base_url}/api/chat"
        payload = {
            "model": self.model,
            "stream": True,
            "messages": [
                {"role": "system", "content": "You are a cybersecurity expert analyzing vulnerability scan results."},
                {"role": "user", "content": prompt}
            ]
        }

        try:
            with httpx.Client(timeout=300.0) as client:
                with client.stream("POST", url, json=payload) as response:
                    response.raise_for_status()
                    content_accumulator = []

                    for line in response.iter_lines():
                        if not line.strip():
                            continue
                        try:
                            chunk = json.loads(line)
                            content_piece = chunk.get("message", {}).get("content", "")
                            if content_piece:
                                content_accumulator.append(content_piece)
                        except json.JSONDecodeError:
                            continue

                    return "".join(content_accumulator).strip()
        except httpx.HTTPError as e:
            raise RuntimeError(f"Ollama API error: {e}. Please check that Ollama is running and accessible.") from e
        except Exception as e:
            raise RuntimeError(f"Ollama connection error: {e}") from e

    async def generate(self, prompt: str) -> str:
        """Generate response using Ollama API (asynchronous)."""
        import json

        url = f"http://{self.base_url}/api/chat"
        payload = {
            "model": self.model,
            "stream": True,
            "messages": [
                {"role": "system", "content": "You are a cybersecurity expert analyzing vulnerability scan results."},
                {"role": "user", "content": prompt}
            ]
        }

        try:
            async with httpx.AsyncClient(timeout=300.0) as client:
                async with client.stream("POST", url, json=payload) as response:
                    response.raise_for_status()
                    content_accumulator = []

                    async for line in response.aiter_lines():
                        if not line.strip():
                            continue
                        try:
                            chunk = json.loads(line)
                            content_piece = chunk.get("message", {}).get("content", "")
                            if content_piece:
                                content_accumulator.append(content_piece)
                        except json.JSONDecodeError:
                            continue

                    return "".join(content_accumulator).strip()
        except httpx.HTTPError as e:
            raise RuntimeError(f"Ollama API error: {e}. Please check that Ollama is running and accessible.") from e
        except Exception as e:
            raise RuntimeError(f"Ollama connection error: {e}") from e


class AnthropicProvider(AIProvider):
    """Anthropic Claude provider."""

    def __init__(self, model: str = "claude-3-5-sonnet-20241022", api_key: Optional[str] = None):
        self.model = model
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable not set")

    def generate_sync(self, prompt: str) -> str:
        """Generate response using Anthropic API (synchronous)."""
        with httpx.Client(timeout=120.0) as client:
            try:
                response = client.post(
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

    async def generate(self, prompt: str) -> str:
        """Generate response using Anthropic API (asynchronous)."""
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

    def generate_sync(self, prompt: str) -> str:
        """Generate response using OpenAI API (synchronous)."""
        with httpx.Client(timeout=120.0) as client:
            try:
                response = client.post(
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

    async def generate(self, prompt: str) -> str:
        """Generate response using OpenAI API (asynchronous)."""
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

    def generate_summary_sync(self, prompt: str) -> str:
        """Generate AI summary (synchronous)."""
        return self.provider.generate_sync(prompt)

    async def generate_summary(self, prompt: str) -> str:
        """Generate AI summary (asynchronous)."""
        return await self.provider.generate(prompt)
