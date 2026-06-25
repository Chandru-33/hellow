"""LLM provider abstraction layer."""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

import httpx


@dataclass
class LLMValidationResult:
    valid: bool
    severity: str
    confidence: int
    reason: str
    fix: str
    provider: str = ""


class LLMProvider(ABC):
    """Abstract LLM provider for finding validation."""

    name: str = "base"

    @abstractmethod
    def validate_finding(
        self,
        issue_type: str,
        category: str,
        code_snippet: str,
        scanner_message: str,
    ) -> LLMValidationResult | None:
        """Validate a finding and return structured result."""

    def _parse_json_response(self, text: str) -> dict[str, Any] | None:
        text = text.strip()
        json_match = re.search(r"\{[\s\S]*\}", text)
        if json_match:
            text = json_match.group(0)
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None

    def _to_result(self, data: dict[str, Any], provider: str) -> LLMValidationResult:
        return LLMValidationResult(
            valid=bool(data.get("valid", False)),
            severity=str(data.get("severity", "Medium")),
            confidence=int(data.get("confidence", 50)),
            reason=str(data.get("reason", "")),
            fix=str(data.get("fix", "")),
            provider=provider,
        )


VALIDATION_PROMPT = """Analyze the following code snippet for a reported security issue.

Issue Type: {issue_type}
Category: {category}
Scanner Message: {scanner_message}

Code Snippet:
```
{code_snippet}
```

Determine:
1. Is this a real security issue?
2. Severity Level (Critical, High, Medium, Low)
3. Confidence Score (0-100)
4. Explanation
5. Recommended Fix (include secure replacement code if applicable)

Return JSON only with this exact structure:
{{
  "valid": true,
  "severity": "Critical",
  "confidence": 97,
  "reason": "...",
  "fix": "..."
}}
"""


class GeminiProvider(LLMProvider):
    name = "gemini"

    def __init__(
        self,
        api_key: str,
        model: str = "gemini-2.5-flash",
    ) -> None:
        self.api_key = api_key
        self.model = model

    def validate_finding(
        self,
        issue_type: str,
        category: str,
        code_snippet: str,
        scanner_message: str,
    ) -> LLMValidationResult | None:

        if not self.api_key:
            return None

        prompt = VALIDATION_PROMPT.format(
            issue_type=issue_type,
            category=category,
            code_snippet=code_snippet,
            scanner_message=scanner_message,
        )

        try:
            from google import genai

            client = genai.Client(
                api_key=self.api_key
            )

            response = client.models.generate_content(
                model=self.model,
                contents=prompt,
            )

            text = ""

            if hasattr(response, "text"):
                text = response.text or ""

            if not text:
                return None

            data = self._parse_json_response(text)

            if data:
                return self._to_result(
                    data,
                    self.name,
                )

        except Exception as e:
            print(f"[Gemini Error] {e}")

        return None


class GroqProvider(LLMProvider):
    name = "groq"

    def __init__(self, api_key: str, model: str = "llama-3.3-70b-versatile") -> None:
        self.api_key = api_key
        self.model = model

    def validate_finding(
        self,
        issue_type: str,
        category: str,
        code_snippet: str,
        scanner_message: str,
    ) -> LLMValidationResult | None:
        if not self.api_key:
            return None
        prompt = VALIDATION_PROMPT.format(
            issue_type=issue_type,
            category=category,
            code_snippet=code_snippet,
            scanner_message=scanner_message,
        )
        try:
            from groq import Groq

            client = Groq(api_key=self.api_key)
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a security expert. Respond with JSON only."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.1,
                max_tokens=1024,
            )
            text = response.choices[0].message.content or ""
            data = self._parse_json_response(text)
            if data:
                return self._to_result(data, self.name)
        except Exception:
            try:
                response = httpx.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.model,
                        "messages": [
                            {"role": "system", "content": "You are a security expert. Respond with JSON only."},
                            {"role": "user", "content": prompt},
                        ],
                        "temperature": 0.1,
                        "max_tokens": 1024,
                    },
                    timeout=30.0,
                )
                response.raise_for_status()
                text = response.json()["choices"][0]["message"]["content"]
                data = self._parse_json_response(text)
                if data:
                    return self._to_result(data, self.name)
            except Exception:
                pass
        return None


class LLMValidator:
    """Orchestrates LLM validation with primary/fallback providers."""

    def __init__(self, config: dict[str, Any]) -> None:
        settings = config.get("_settings")
        gemini_key = settings.gemini_api_key if settings else ""
        groq_key = settings.groq_api_key if settings else ""

        self.providers: list[LLMProvider] = []
        primary = config.get("llm_provider", "gemini")

        gemini = GeminiProvider(gemini_key, config.get("llm_model_gemini", "gemini-2.5-flash"))
        groq = GroqProvider(groq_key, config.get("llm_model_groq", "llama-3.3-70b-versatile"))

        if primary == "gemini":
            self.providers = [gemini, groq]
        else:
            self.providers = [groq, gemini]

        self.enabled = config.get("enable_llm", True)
        self.context_lines = config.get("snippet_context_lines", 20)

    def validate(
        self,
        issue_type: str,
        category: str,
        code_snippet: str,
        scanner_message: str,
    ) -> LLMValidationResult | None:
        if not self.enabled:
            return None
        for provider in self.providers:
            result = provider.validate_finding(issue_type, category, code_snippet, scanner_message)
            if result is not None:
                return result
        return None

    def has_available_provider(self) -> bool:
        if not self.enabled:
            return False
        for provider in self.providers:
            if isinstance(provider, GeminiProvider) and provider.api_key:
                return True
            if isinstance(provider, GroqProvider) and provider.api_key:
                return True
        return False

    def active_provider_name(self) -> str:
        if not self.enabled:
            return ""
        for provider in self.providers:
            if isinstance(provider, GeminiProvider) and provider.api_key:
                return provider.name
            if isinstance(provider, GroqProvider) and provider.api_key:
                return provider.name
        return ""
