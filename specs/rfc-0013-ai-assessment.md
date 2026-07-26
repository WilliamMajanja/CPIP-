# RFC-0013: AI Threat Assessment Engine

| Field | Value |
|-------|-------|
| Status | Draft |
| Component | `providers/ai_assessor.py` |
| Related | RFC-0006 |
| Version Target | v6.0.0 |

## Abstract

Local LLM (via llama.cpp) or cloud API generates natural-language threat
briefings from structured threat event data.

## Design

- Local mode: llama.cpp with 3B-7B model (Phi-3, Mistral)
- Cloud mode: POST to OpenAI/Anthropic/Ollama with threat event JSON
- Output: plain-English summary, severity, recommended actions
- Voice briefing via espeak/piper TTS for hands-free

## CLI

```
cpip assess now
cpip assess summary [daily|weekly]
cpip assess listen
```

## Env

```
CPIP_AI_ASSESSOR=0
CPIP_AI_MODE=local|cloud
CPIP_AI_LLAMA_MODEL=/models/phi-3-mini.Q4_K_M.gguf
CPIP_AI_API_URL=https://api.openai.com/v1/chat/completions
CPIP_AI_API_KEY=
CPIP_AI_TTS=espeak|piper|none
```
