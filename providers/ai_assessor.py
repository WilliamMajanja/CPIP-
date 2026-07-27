from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
import time
from typing import Any, ClassVar

from providers.base import BaseProvider, ProviderType

logger = logging.getLogger(__name__)

AI_ASSESSOR_ENABLED = os.environ.get("CPIP_AI_ASSESSOR", "0") == "1"
AI_MODE = os.environ.get("CPIP_AI_MODE", "local")
AI_LLAMA_MODEL = os.environ.get("CPIP_AI_LLAMA_MODEL", "")
AI_API_URL = os.environ.get("CPIP_AI_API_URL", "")
AI_API_KEY = os.environ.get("CPIP_AI_API_KEY", "")
AI_TTS = os.environ.get("CPIP_AI_TTS", "none")


class AIAssessorProvider(BaseProvider):
    TYPE = ProviderType.INTELLIGENCE
    NAME = "ai_assessor"
    VERSION = "6.0.3"

    _assessments: list[dict] = []

    @classmethod
    def is_available(cls) -> bool:
        if AI_MODE == "local":
            return bool(AI_LLAMA_MODEL) and os.path.exists(AI_LLAMA_MODEL)
        return bool(AI_API_URL) and bool(AI_API_KEY)

    @classmethod
    def assess(cls, threat_events: list[dict], score: float, location: str = "") -> dict:
        prompt = cls._build_prompt(threat_events, score, location)
        if AI_MODE == "local":
            result = cls._query_local(prompt)
        else:
            result = cls._query_api(prompt)
        assessment = {
            "timestamp": time.time(),
            "score": score,
            "events_count": len(threat_events),
            "summary": result.get("summary", "Assessment unavailable"),
            "severity": result.get("severity", "unknown"),
            "actions": result.get("actions", []),
        }
        cls._assessments.append(assessment)
        if len(cls._assessments) > 100:
            cls._assessments = cls._assessments[-100:]
        return assessment

    @classmethod
    def _build_prompt(cls, events: list[dict], score: float, location: str) -> str:
        events_str = json.dumps(events, indent=2) if events else "No recent events"
        return (
            f"You are a cellular security threat assessor.\n"
            f"Current threat score: {score:.2f}/1.00\n"
            f"Node location: {location or 'unknown'}\n"
            f"Recent threat events:\n{events_str}\n\n"
            f"Provide: 1) A 2-3 sentence plain-English summary of the current threat posture. "
            f"2) A severity rating (LOW/MEDIUM/HIGH/CRITICAL). "
            f"3) 2-3 recommended actions. "
            f"Format as JSON: {{\"summary\":\"...\",\"severity\":\"...\",\"actions\":[\"...\"]}}"
        )

    @classmethod
    def _query_local(cls, prompt: str) -> dict:
        try:
            result = subprocess.run(
                ["llama-cli", "-m", AI_LLAMA_MODEL, "-p", prompt, "--temp", "0.2", "-n", "512"],
                capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                return json.loads(result.stdout)
        except Exception as e:
            logger.debug("Local LLM error: %s", e)
        return {"summary": "Local LLM unavailable", "severity": "unknown", "actions": []}

    @classmethod
    def _query_api(cls, prompt: str) -> dict:
        try:
            import urllib.request
            body = json.dumps({
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2,
            }).encode()
            req = urllib.request.Request(AI_API_URL, data=body,
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {AI_API_KEY}"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
                content = data["choices"][0]["message"]["content"]
                return json.loads(content)
        except Exception as e:
            logger.debug("API assess error: %s", e)
        return {"summary": "API assessment failed", "severity": "unknown", "actions": []}

    @classmethod
    def get_status(cls) -> dict[str, Any]:
        return {
            "enabled": AI_ASSESSOR_ENABLED,
            "mode": AI_MODE,
            "available": cls.is_available(),
            "assessments_count": len(cls._assessments),
            "last_assessment": cls._assessments[-1] if cls._assessments else None,
        }
