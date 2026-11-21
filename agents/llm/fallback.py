
"""LLM fallback provider for transient API failures."""

import logging
from typing import Sequence

from google.genai.errors import APIError
from openai import (
    APIConnectionError,
    APITimeoutError,
    InternalServerError,
    RateLimitError,
)

from .providers import LLMProvider, LLMResponse, Message, StructuredResponse

logger = logging.getLogger(__name__)

RETRYABLE_ERRORS = (
    APIConnectionError,
    APITimeoutError,
    InternalServerError,
    RateLimitError,
)

GEMINI_RETRYABLE_CODES = {429, 500, 502, 503, 504}


class FallbackProvider(LLMProvider):
    """Use a secondary provider when the primary has a temporary failure."""

    def __init__(self, primary: LLMProvider, secondary: LLMProvider):
        super().__init__(primary.model)
        self.primary = primary
        self.secondary = secondary

    def _execute(self, method, *args, **kwargs):
        try:
            return getattr(self.primary, method)(*args, **kwargs)

        except APIError as exc:
            if getattr(exc, "code", None) not in GEMINI_RETRYABLE_CODES:
                raise

            logger.warning(
                "Primary Gemini provider unavailable (API error %s). "
                "Switching to secondary provider.",
                getattr(exc, "code", "unknown"),
            )
            return getattr(self.secondary, method)(*args, **kwargs)

        except RETRYABLE_ERRORS as exc:
            logger.warning(
                "Primary LLM provider unavailable (%s). "
                "Switching to secondary provider.",
                type(exc).__name__,
            )
            return getattr(self.secondary, method)(*args, **kwargs)

    def generate(self, prompt: str, *, temperature: float = 0.2) -> LLMResponse:
        return self._execute("generate", prompt, temperature=temperature)

    def chat(
        self,
        messages: Sequence[Message],
        *,
        temperature: float = 0.2,
    ) -> LLMResponse:
        return self._execute("chat", messages, temperature=temperature)

    def structured(
        self,
        messages: Sequence[Message],
        response_model: type[StructuredResponse],
        *,
        temperature: float = 0.0,
    ) -> StructuredResponse:
        return self._execute(
            "structured",
            messages,
            response_model,
            temperature=temperature,
        )

    def health_check(self) -> tuple[bool, str]:
        return self.primary.health_check()
