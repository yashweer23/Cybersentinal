"""Optional OpenAI Responses adapter: bounded output, no tools and no arbitrary endpoint."""

import json
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from time import perf_counter

import httpx

from app.ai.prompts import CORRECTION, SYSTEM_PROMPT
from app.ai.providers.base import ProviderResult
from app.ai.providers.fallback import FallbackAnalyst
from app.ai.schemas import EvidencePlan
from app.ai.validation import validate_plan


def retry_hint(value):
    try:
        return max(1, min(86400, int(value)))
    except (ValueError, TypeError):
        try:
            return max(
                1,
                min(86400, int((parsedate_to_datetime(value) - datetime.now(UTC)).total_seconds())),
            )
        except (ValueError, TypeError, OverflowError):
            return None


class LLMProvider:
    def __init__(self, settings, transport=None):
        self.settings, self.transport = settings, transport

    def is_configured(self):
        return (
            self.settings.ai_provider == "openai"
            and bool(self.settings.ai_api_key.get_secret_value().strip())
            and bool(self.settings.ai_model)
        )

    def generate(self, catalog):
        started = perf_counter()
        failure, hint = "not_configured", None
        if self.is_configured():
            deadline = started + self.settings.ai_request_timeout_seconds
            with httpx.Client(
                transport=self.transport, follow_redirects=False, trust_env=False
            ) as client:
                for attempt in range(2):
                    remaining = deadline - perf_counter()
                    if remaining <= 0:
                        failure = "timeout"
                        break
                    payload = {
                        "model": self.settings.ai_model,
                        "store": False,
                        "max_output_tokens": self.settings.ai_max_response_tokens,
                        "input": [
                            {
                                "role": "system",
                                "content": SYSTEM_PROMPT + (CORRECTION if attempt else ""),
                            },
                            {
                                "role": "user",
                                "content": json.dumps(catalog.payload(), separators=(",", ":")),
                            },
                        ],
                        "text": {
                            "format": {
                                "type": "json_schema",
                                "name": "evidence_plan",
                                "strict": True,
                                "schema": EvidencePlan.model_json_schema(),
                            }
                        },
                    }
                    try:
                        with client.stream(
                            "POST",
                            "https://api.openai.com/v1/responses",
                            json=payload,
                            headers={
                                "Authorization": "Bearer "
                                + self.settings.ai_api_key.get_secret_value()
                            },
                            timeout=min(remaining, self.settings.ai_request_timeout_seconds / 2),
                        ) as response:
                            if response.status_code == 429:
                                failure, hint = (
                                    "rate_limited",
                                    retry_hint(response.headers.get("Retry-After")),
                                )
                                break
                            if response.status_code in {401, 403}:
                                failure = "authentication_failed"
                                break
                            if response.status_code >= 500:
                                failure = "unavailable"
                                if response.headers.get("Retry-After"):
                                    hint = retry_hint(response.headers["Retry-After"])
                                    break
                                continue
                            if response.status_code != 200:
                                failure = "request_rejected"
                                break
                            body = bytearray()
                            for chunk in response.iter_bytes():
                                body.extend(chunk)
                                if len(body) > 65536 or perf_counter() > deadline:
                                    raise ValueError("Provider response exceeded budget")
                        result = json.loads(body)
                        if result.get("status") != "completed":
                            raise ValueError("Incomplete response")
                        texts = [
                            part["text"]
                            for item in result.get("output", [])
                            if item.get("type") == "message"
                            for part in item.get("content", [])
                            if part.get("type") == "output_text"
                        ]
                        if len(texts) != 1:
                            raise ValueError("Missing structured output")
                        plan = validate_plan(texts[0], catalog)
                        return ProviderResult(
                            plan,
                            "AI",
                            "openai",
                            self.settings.ai_model,
                            duration_ms=round((perf_counter() - started) * 1000, 3),
                        )
                    except httpx.TimeoutException:
                        failure = "timeout"
                    except httpx.HTTPError:
                        failure = "unavailable"
                    except (ValueError, KeyError, TypeError, AttributeError):
                        failure = "invalid_output"
        result = FallbackAnalyst().generate(catalog)
        result.failure, result.retry_after_seconds = failure, hint
        result.duration_ms = round((perf_counter() - started) * 1000, 3)
        return result
