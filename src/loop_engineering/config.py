"""Runtime configuration for the malware intelligence loop."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os


DEFAULT_ENDPOINT = "https://mb-api.abuse.ch/api/v1/"


@dataclass(frozen=True)
class Settings:
    malwarebazaar_auth_key: str
    malwarebazaar_endpoint: str
    reports_dir: Path
    quarantine_dir: Path
    allow_raw_download: bool

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            malwarebazaar_auth_key=os.getenv("MALWAREBAZAAR_AUTH_KEY", "").strip(),
            malwarebazaar_endpoint=os.getenv("MALWAREBAZAAR_ENDPOINT", DEFAULT_ENDPOINT).strip(),
            reports_dir=Path(os.getenv("LOOP_REPORTS_DIR", "reports")),
            quarantine_dir=Path(os.getenv("LOOP_QUARANTINE_DIR", "quarantine")),
            allow_raw_download=os.getenv("LOOP_ALLOW_MALWARE_DOWNLOAD", "") == "1",
        )

    def require_malwarebazaar_key(self) -> None:
        if not self.malwarebazaar_auth_key:
            raise ConfigError("MALWAREBAZAAR_AUTH_KEY is required for MalwareBazaar API calls")


class ConfigError(RuntimeError):
    """Raised when required runtime configuration is missing."""
