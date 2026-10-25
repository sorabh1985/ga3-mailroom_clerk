"""Minimal OpenAI-compatible chat client with bounded time, size and retries.

Default provider: Google Gemini free tier via its OpenAI-compatible endpoint.
Any other OpenAI-compatible free provider (Groq, OpenRouter, Cerebras...) works by
changing LLM_BASE_URL / LLM_MODEL / LLM_API_KEY.
"""
import asyncio
import json
import os
import re
import time

import httpx

MAX_CONTENT_CHARS = 300_000
RECENT = []  # last few attempts in this process, for the ?diag=1 page


def _note(model, status, t0):
    RECENT.append({"model": model, "status": status, "seconds": round(time.monotonic() - t0, 1)})
    del RECENT[:-12]


class LLMError(Exception):
    pass


def config():
    return {
        "base_url": os.environ.get("LLM_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai").rstrip("/"),
        "api_key": os.environ.get("LLM_API_KEY") or os.environ.get("GEMINI_API_KEY", ""),
        "model": os.environ.get("LLM_MODEL", "gemini-3.6-flash"),
        "fallback_model": os.environ.get("LLM_FALLBACK_MODEL", "gemini-3.8-flash"),
        "reasoning_effort": os.environ.get("LLM_REASONING_EFFORT", "low"),
        "max_tokens": int(os.environ.get("LLM_MAX_TOKENS", "16000")),
    }


def _extract_json(text: str):
    text = text.strip()
    m = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if m:
        text = m.group(1).strip()
    if not text.startswith("{"):
        i, j = text.find("{"), text.rfind("}")
        if i >= 0 and j > i:
            text = text[i:j + 1]
    return json.loads(text)


async def chat_json(system: str, user: str, deadline: float):
    """Return parsed JSON object from the model, or raise LLMError. Never exceeds deadline."""
    cfg = config()
    if not cfg["api_key"]:
        raise LLMError("no LLM API key configured")
    models = [cfg["model"]] + ([cfg["fallback_model"]] if cfg["fallback_model"] and cfg["fallback_model"] != cfg["model"] else [])
    last = None
    use_fallback = False
    for attempt in range(3):
        model = models[-1] if use_fallback else models[0]
        remaining = deadline - time.monotonic()
        if remaining < 3:
            break
        body = {
            "model": model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": 0,
            "max_tokens": cfg["max_tokens"],
            "response_format": {"type": "json_object"},
        }
        effort = os.environ.get("LLM_REASONING_EFFORT", "low")
        if effort and effort != "off":
            body["reasoning_effort"] = effort
        t_call = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(remaining - 1, connect=5.0)) as c:
                r = await c.post(f"{cfg['base_url']}/chat/completions",
                                 headers={"Authorization": f"Bearer {cfg['api_key']}"}, json=body)
            _note(model, r.status_code, t_call)
            if r.status_code != 200:
                last = LLMError(f"HTTP {r.status_code}: {r.text[:300]}")
                if r.status_code == 429 or r.status_code >= 500:
                    use_fallback = not use_fallback  # quota hit or model overloaded: alternate models
                if r.status_code in (400, 401, 403, 404) and "reasoning" in r.text.lower() and "reasoning_effort" in body:
                    os.environ["LLM_REASONING_EFFORT"] = "off"  # provider does not support it
                await asyncio.sleep(min(2.0 * (attempt + 1), max(0.0, deadline - time.monotonic() - 3)))
                continue
            data = r.json()
            content = (data.get("choices") or [{}])[0].get("message", {}).get("content") or ""
            if len(content) > MAX_CONTENT_CHARS:
                raise LLMError("model output too large")
            return _extract_json(content)
        except (httpx.HTTPError, ValueError, KeyError, IndexError) as e:
            _note(model, type(e).__name__, t_call)
            last = LLMError(f"{type(e).__name__}: {str(e)[:200]}")
    raise last or LLMError("deadline reached before model call")
