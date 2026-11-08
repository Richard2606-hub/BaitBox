"""
BaitBox — Control Plane Configuration (backend/app/config.py)
=============================================================
Loads environment settings for the trusted control plane on the Vultr VM.
API keys remain strictly inside this process and are NEVER passed to the
disposable detonation chamber.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DATA_DIR = BASE_DIR / "data"


@dataclass(frozen=True)
class Settings:
    # Mode: "production" or "local"
    mode: str = os.getenv("BAITBOX_MODE", "local")

    # Vultr Serverless Inference (OpenAI-compatible API)
    vultr_inference_base_url: str = os.getenv(
        "VULTR_INFERENCE_BASE_URL", "https://api.vultrinference.com/v1"
    )
    vultr_inference_api_key: str = os.getenv("VULTR_INFERENCE_API_KEY", "")
    vultr_planner_model: str = os.getenv(
        "VULTR_PLANNER_MODEL", "qwen2.5-coder-32b-instruct"
    )
    vultr_vision_model: str = os.getenv(
        "VULTR_VISION_MODEL", "qwen2.5-vl-72b-instruct"
    )

    # M4 Chamber Manager settings
    chamber_backend: str = os.getenv("CHAMBER_BACKEND", "auto")
    chamber_image: str = os.getenv("CHAMBER_IMAGE", "baitbox-chamber:latest")
    egress_image: str = os.getenv("EGRESS_IMAGE", "baitbox-egress:latest")
    chamber_max_age_seconds: int = int(os.getenv("CHAMBER_MAX_AGE_SECONDS", "90"))
    chamber_sweep_interval_seconds: int = int(
        os.getenv("CHAMBER_SWEEP_INTERVAL_SECONDS", "60")
    )
    chamber_cpu_limit: float = float(os.getenv("CHAMBER_CPU_LIMIT", "1.0"))
    chamber_mem_limit: str = os.getenv("CHAMBER_MEM_LIMIT", "1g")
    chamber_pids_limit: int = int(os.getenv("CHAMBER_PIDS_LIMIT", "256"))

    # M2 & M3 Agent Loop & Policy Gate settings
    max_agent_steps: int = int(os.getenv("MAX_AGENT_STEPS", "8"))
    require_approval_default: bool = (
        os.getenv("REQUIRE_APPROVAL_FOR_INTERACTION", "false").lower() == "true"
    )

    # M8 Evidence Store settings
    data_dir: Path = Path(os.getenv("DATA_DIR", str(DEFAULT_DATA_DIR)))
    retention_days: int = int(os.getenv("RETENTION_DAYS", "7"))

    # Server URLs
    control_plane_host: str = os.getenv("CONTROL_PLANE_HOST", "0.0.0.0")
    control_plane_port: int = int(os.getenv("CONTROL_PLANE_PORT", "8000"))
    public_base_url: str = os.getenv("PUBLIC_BASE_URL", "http://localhost:8000")

    @property
    def db_path(self) -> Path:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        return self.data_dir / "baitbox.db"

    @property
    def screenshots_dir(self) -> Path:
        path = self.data_dir / "screenshots"
        path.mkdir(parents=True, exist_ok=True)
        return path


settings = Settings()
