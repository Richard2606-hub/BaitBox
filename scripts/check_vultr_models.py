#!/usr/bin/env python3
"""
BaitBox — Block 1: Vultr Serverless Inference & Model Catalog Inspector
=======================================================================
Connects to https://api.vultrinference.com/v1 using both:
1. Official `vultr-model-catalog` (or direct GET /v1/models with local disk cache)
   to discover agent-ready and vision-capable models without requiring an API key.
2. OpenAI-compatible client pointed at `https://api.vultrinference.com/v1`
   to verify live chat/vision completion when VULTR_INFERENCE_API_KEY is configured.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

import httpx

VULTR_BASE_URL = os.getenv("VULTR_INFERENCE_BASE_URL", "https://api.vultrinference.com/v1")
CACHE_PATH = Path(".vultr-catalog.json")


def discover_vultr_models(base_url: str = VULTR_BASE_URL) -> Dict[str, Any]:
    """
    Discovers available models from Vultr Serverless Inference.
    Uses `vultr_model_catalog` if installed, otherwise queries `GET /v1/models`
    directly and caches results in `.vultr-catalog.json`.
    """
    result: Dict[str, Any] = {
        "base_url": base_url,
        "source": "unknown",
        "all_models": [],
        "agent_models": [],
        "vision_models": [],
        "recommended_planner": "qwen2.5-coder-32b-instruct",
        "recommended_vision": "qwen2.5-vl-72b-instruct",
    }

    # 1. Try official vultr_model_catalog SDK first
    try:
        from vultr_model_catalog import load_catalog  # type: ignore

        catalog = load_catalog(
            base_url=base_url,
            cache_path=str(CACHE_PATH),
            max_age=300,
        )
        result["source"] = "vultr_model_catalog"
        for m in getattr(catalog, "models", []):
            model_id = getattr(m, "id", str(m))
            result["all_models"].append(model_id)
            if any(v in model_id.lower() for v in ("vl", "vision", "pixtral", "llava", "gpt-4o", "claude-3", "gemini")):
                result["vision_models"].append(model_id)
        for m in getattr(catalog, "agent_models", []):
            result["agent_models"].append(getattr(m, "id", str(m)))
    except Exception:
        # 2. Fallback to direct OpenAI-compatible GET /v1/models endpoint
        try:
            with httpx.Client(timeout=8.0) as client:
                resp = client.get(f"{base_url.rstrip('/')}/models")
                if resp.status_code == 200:
                    payload = resp.json()
                    CACHE_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
                    result["source"] = "live_http_api"
                    models_list: List[Any] = payload.get("data", payload.get("models", []))
                    for item in models_list:
                        if isinstance(item, dict):
                            model_id = item.get("id", "")
                            in_mods = [
                                m.get("type", "")
                                for m in item.get("input_modalities", [])
                                if isinstance(m, dict)
                            ]
                            out_mods = [
                                m.get("type", "")
                                for m in item.get("output_modalities", [])
                                if isinstance(m, dict)
                            ]
                            result["all_models"].append(model_id)
                            if "text" in out_mods and "image" in in_mods:
                                result["vision_models"].append(model_id)
                            if "text" in out_mods:
                                result["agent_models"].append(model_id)
                        else:
                            model_id = str(item)
                            result["all_models"].append(model_id)
        except Exception as exc:
            result["source"] = f"offline_fallback ({type(exc).__name__})"
            if CACHE_PATH.exists():
                try:
                    cached = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
                    for item in cached.get("data", []):
                        model_id = item.get("id", str(item)) if isinstance(item, dict) else str(item)
                        result["all_models"].append(model_id)
                except Exception:
                    pass

    if result["agent_models"]:
        result["recommended_planner"] = result["agent_models"][0]
    elif result["all_models"]:
        result["recommended_planner"] = result["all_models"][0]

    if result["vision_models"]:
        result["recommended_vision"] = result["vision_models"][0]
    elif result["all_models"]:
        result["recommended_vision"] = result["all_models"][0]

    return result


def verify_openai_client(base_url: str = VULTR_BASE_URL) -> None:
    """
    Demonstrates calling Vultr Serverless Inference via the OpenAI Python SDK
    as specified in Block 1 of the BaitBox Technical Design Document.
    """
    api_key = os.getenv("VULTR_INFERENCE_API_KEY", "").strip()
    catalog_info = discover_vultr_models(base_url)

    print("=" * 72)
    print("BaitBox — Vultr Serverless Inference Model Catalog Check")
    print("=" * 72)
    print(f"Endpoint Base URL     : {base_url}")
    print(f"Catalog Source        : {catalog_info['source']}")
    print(f"Total Models Found    : {len(catalog_info['all_models'])}")
    print(f"Recommended Planner   : {catalog_info['recommended_planner']}")
    print(f"Recommended Vision    : {catalog_info['recommended_vision']}")
    if catalog_info["all_models"]:
        print(f"Sample Models         : {', '.join(catalog_info['all_models'][:8])}")

    if not api_key:
        print("-" * 72)
        print("NOTE: VULTR_INFERENCE_API_KEY is not set in environment.")
        print("BaitBox will run in Local Deterministic Sandbox Mode until an API key is provided.")
        print("=" * 72)
        return

    try:
        from openai import OpenAI

        client = OpenAI(api_key=api_key, base_url=base_url)
        models = client.models.list()
        model_ids = [m.id for m in models.data]
        print(f"Authenticated Models  : {len(model_ids)} available via OpenAI SDK")
    except Exception as exc:
        print(f"OpenAI SDK Check Note : {exc}")
    print("=" * 72)


if __name__ == "__main__":
    verify_openai_client()
    sys.exit(0)
