"""
SecOps AI Assistant — LLM Client

Abstraction layer supporting OpenAI and Google Gemini with automatic failover,
token counting, cost estimation, and retry logic.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Optional

from app.config import LLMProvider, get_settings

logger = logging.getLogger(__name__)


class LLMResponse:
    """Standardized response from any LLM provider."""

    def __init__(
        self,
        content: str,
        provider: str,
        model: str,
        input_tokens: int = 0,
        output_tokens: int = 0,
        latency_ms: float = 0.0,
    ):
        self.content = content
        self.provider = provider
        self.model = model
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.total_tokens = input_tokens + output_tokens
        self.latency_ms = latency_ms

    @property
    def estimated_cost(self) -> float:
        """Estimate cost in USD based on provider and model."""
        cost_per_1k = {
            "gpt-4o": {"input": 0.0025, "output": 0.01},
            "gpt-4o-mini": {"input": 0.00015, "output": 0.0006},
            "gpt-4-turbo": {"input": 0.01, "output": 0.03},
            "gemini-2.0-flash": {"input": 0.0001, "output": 0.0004},
            "gemini-1.5-pro": {"input": 0.00125, "output": 0.005},
            "gemini-1.5-flash": {"input": 0.000075, "output": 0.0003},
        }
        rates = cost_per_1k.get(self.model, {"input": 0.001, "output": 0.002})
        return round(
            (self.input_tokens / 1000) * rates["input"]
            + (self.output_tokens / 1000) * rates["output"],
            6,
        )

    def parse_json(self) -> dict:
        """Parse the response content as JSON, handling markdown code blocks."""
        content = self.content.strip()
        # Remove markdown code blocks if present
        if content.startswith("```"):
            lines = content.split("\n")
            # Remove first line (```json) and last line (```)
            lines = [l for l in lines if not l.strip().startswith("```")]
            content = "\n".join(lines)
        return json.loads(content)


class LLMClient:
    """
    Multi-provider LLM client with failover.

    Supports OpenAI and Google Gemini, with automatic failover
    if the primary provider fails.
    """

    def __init__(self):
        self.settings = get_settings()
        self._openai_client = None
        self._gemini_model = None
        self._semaphore = asyncio.Semaphore(self.settings.llm_max_concurrent)

    def _get_openai_client(self):
        """Lazy-init OpenAI client."""
        if self._openai_client is None and self.settings.has_openai:
            from openai import AsyncOpenAI
            self._openai_client = AsyncOpenAI(api_key=self.settings.openai_api_key)
        return self._openai_client

    def _get_gemini_model(self):
        """Lazy-init Gemini client."""
        if self._gemini_model is None and self.settings.has_gemini:
            import google.generativeai as genai
            genai.configure(api_key=self.settings.google_api_key)
            self._gemini_model = genai.GenerativeModel(self.settings.google_model)
        return self._gemini_model

    async def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        response_format: str = "json",
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """
        Send a completion request to the LLM.

        Tries the primary provider first, falls back to secondary on failure.
        """
        if self.settings.is_demo_mode:
            raise RuntimeError("No LLM API keys configured. Running in demo mode.")

        async with self._semaphore:
            primary = self.settings.active_provider
            fallback = self.settings.fallback_provider

            # Try primary
            try:
                return await self._call_with_retry(
                    primary, system_prompt, user_prompt,
                    response_format, temperature, max_tokens,
                )
            except Exception as primary_error:
                logger.error(f"Primary LLM ({primary}) failed: {primary_error}")

                # Try fallback
                if fallback:
                    try:
                        logger.info(f"Falling back to {fallback}")
                        return await self._call_with_retry(
                            fallback, system_prompt, user_prompt,
                            response_format, temperature, max_tokens,
                        )
                    except Exception as fallback_error:
                        logger.error(f"Fallback LLM ({fallback}) also failed: {fallback_error}")
                        raise RuntimeError(
                            f"Both LLM providers failed. Primary ({primary}): {primary_error}. "
                            f"Fallback ({fallback}): {fallback_error}"
                        ) from fallback_error
                else:
                    raise

    async def _call_with_retry(
        self,
        provider: LLMProvider,
        system_prompt: str,
        user_prompt: str,
        response_format: str,
        temperature: float,
        max_tokens: int,
    ) -> LLMResponse:
        """Call LLM with retry and exponential backoff."""
        last_error = None
        for attempt in range(self.settings.llm_retry_attempts):
            try:
                if provider == LLMProvider.OPENAI:
                    return await self._call_openai(
                        system_prompt, user_prompt, response_format,
                        temperature, max_tokens,
                    )
                elif provider == LLMProvider.GEMINI:
                    return await self._call_gemini(
                        system_prompt, user_prompt, response_format,
                        temperature, max_tokens,
                    )
                else:
                    raise ValueError(f"Unknown provider: {provider}")
            except Exception as e:
                last_error = e
                if attempt < self.settings.llm_retry_attempts - 1:
                    backoff = self.settings.llm_retry_backoff_seconds * (2 ** attempt)
                    logger.warning(
                        f"LLM attempt {attempt + 1} failed: {e}. "
                        f"Retrying in {backoff}s..."
                    )
                    await asyncio.sleep(backoff)

        raise last_error  # type: ignore

    async def _call_openai(
        self,
        system_prompt: str,
        user_prompt: str,
        response_format: str,
        temperature: float,
        max_tokens: int,
    ) -> LLMResponse:
        """Call OpenAI API."""
        client = self._get_openai_client()
        if client is None:
            raise RuntimeError("OpenAI client not configured")

        start = time.time()

        kwargs: dict[str, Any] = {
            "model": self.settings.openai_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        if response_format == "json":
            kwargs["response_format"] = {"type": "json_object"}

        response = await client.chat.completions.create(**kwargs)

        latency = (time.time() - start) * 1000
        usage = response.usage

        return LLMResponse(
            content=response.choices[0].message.content or "",
            provider="openai",
            model=self.settings.openai_model,
            input_tokens=usage.prompt_tokens if usage else 0,
            output_tokens=usage.completion_tokens if usage else 0,
            latency_ms=round(latency, 2),
        )

    async def _call_gemini(
        self,
        system_prompt: str,
        user_prompt: str,
        response_format: str,
        temperature: float,
        max_tokens: int,
    ) -> LLMResponse:
        """Call Google Gemini API."""
        model = self._get_gemini_model()
        if model is None:
            raise RuntimeError("Gemini model not configured")

        start = time.time()

        combined_prompt = f"{system_prompt}\n\n---\n\n{user_prompt}"

        if response_format == "json":
            combined_prompt += "\n\nIMPORTANT: Respond ONLY with valid JSON. No markdown, no explanation."

        # Run sync Gemini call in executor
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: model.generate_content(
                combined_prompt,
                generation_config={
                    "temperature": temperature,
                    "max_output_tokens": max_tokens,
                },
            ),
        )

        latency = (time.time() - start) * 1000

        # Estimate tokens (Gemini doesn't always provide exact counts)
        input_tokens = len(combined_prompt) // 4  # rough estimate
        output_text = response.text or ""
        output_tokens = len(output_text) // 4

        return LLMResponse(
            content=output_text,
            provider="gemini",
            model=self.settings.google_model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_ms=round(latency, 2),
        )
