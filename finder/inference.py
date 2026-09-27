"""Thin client for Vultr Serverless Inference (OpenAI-compatible).

All finder *reasoning* must go through Vultr Serverless Inference (a hard
requirement of the challenge). This module is the only place that talks to it.

If no inference key is configured, `InferenceClient.available` is False and the
caller falls back to a deterministic offline heuristic. We never pretend the
model ran: the triage `source` records exactly which path produced the plan.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import httpx
from dotenv import load_dotenv

BASE_URL = "https://api.vultrinference.com/v1"

# Preference order for a tool-calling / instruct model. We match by substring
# against the LIVE /models list rather than hard-coding an id, because the exact
# ids are emailed at kickoff and change between decks.
MODEL_PREFERENCE = ("deepseek", "qwen", "glm", "kimi", "minimax", "mimo", "laguna")

# Reranker / retriever / image / safety-only models are not chat models.
MODEL_EXCLUDE = ("reranker", "retriever", "image", "content-safety", "omni")


def _load_inference_key() -> str | None:
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
    return (
        os.getenv("VULTR_INFERENCE_API_KEY")
        or os.getenv("VULTR_INFERENCE_KEY")
        or os.getenv("vultr_inference_api_key")
        or os.getenv("OPENAI_API_KEY")
    )


class InferenceClient:
    def __init__(self, model: str | None = None, timeout: float = 45.0):
        self._key = _load_inference_key()
        self._timeout = timeout
        self._model = model or os.getenv("FINDER_MODEL")
        self.last_error: str | None = None

    @property
    def available(self) -> bool:
        return bool(self._key)

    def pick_model(self) -> str | None:
        """Choose a tool-calling model from the live /models list."""
        if self._model:
            return self._model
        if not self.available:
            return None
        try:
            with httpx.Client(timeout=self._timeout) as client:
                resp = client.get(
                    f"{BASE_URL}/models",
                    headers={"Authorization": f"Bearer {self._key}"},
                )
                resp.raise_for_status()
                ids = [m["id"] for m in resp.json()["data"]]
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            self.last_error = f"model list failed: {exc}"
            return None
        chat_ids = [i for i in ids if not any(x in i.lower() for x in MODEL_EXCLUDE)]
        for pref in MODEL_PREFERENCE:
            for i in chat_ids:
                if pref in i.lower():
                    self._model = i
                    return i
        if chat_ids:
            self._model = chat_ids[0]
        return self._model

    def complete_json(self, system: str, user: str) -> dict | None:
        """Run one chat completion and parse a JSON object from the reply.

        Returns None (and sets last_error) on any failure so the caller can fall
        back to the offline heuristic instead of crashing the run.
        """
        model = self.pick_model()
        if not self.available or not model:
            self.last_error = self.last_error or "no inference key configured"
            return None
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.1,
            "max_tokens": 1500,
        }
        try:
            with httpx.Client(timeout=self._timeout) as client:
                resp = client.post(
                    f"{BASE_URL}/chat/completions",
                    headers={"Authorization": f"Bearer {self._key}"},
                    json=payload,
                )
                resp.raise_for_status()
                content = resp.json()["choices"][0]["message"]["content"]
        except (httpx.HTTPError, KeyError, ValueError, IndexError) as exc:
            self.last_error = f"inference call failed: {exc}"
            return None
        return _extract_json(content)

    @property
    def model_label(self) -> str:
        return f"vultr-inference:{self._model}" if self._model else "vultr-inference:unknown"


def _extract_json(text: str) -> dict | None:
    """Pull the first JSON object out of a model reply (handles code fences)."""
    if not text:
        return None
    fenced = text.strip()
    if "```" in fenced:
        parts = fenced.split("```")
        for part in parts:
            part = part.strip()
            if part.startswith("json"):
                part = part[4:].strip()
            if part.startswith("{"):
                fenced = part
                break
    start = fenced.find("{")
    end = fenced.rfind("}")
    if start == -1 or end == -1 or end < start:
        return None
    try:
        return json.loads(fenced[start : end + 1])
    except json.JSONDecodeError:
        return None
