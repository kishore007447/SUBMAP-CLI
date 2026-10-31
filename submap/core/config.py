"""Core configuration and data models for SUBMAP."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class ScanConfig(BaseModel):
    """Full scan configuration passed to the engine."""

    # targets
    targets: list[str] = Field(default_factory=list)
    output_dir: Optional[Path] = None
    save: bool = False
    resume: bool = False
    exclude: list[str] = Field(default_factory=list)
    include: list[str] = Field(default_factory=list)

    # discovery
    passive: bool = True
    active: bool = False
    bruteforce: bool = False
    recursive: bool = False
    wordlist: Optional[Path] = None
    resolvers: Optional[Path] = None

    # recon modules
    live: bool = True
    dns: bool = True
    ports: bool = False
    tech: bool = True
    api: bool = False
    urls: bool = False
    js: bool = False
    leaks: bool = False
    tls: bool = True
    headers: bool = True
    cloud: bool = False

    # performance
    threads: int = 10
    timeout: int = 10
    retries: int = 2
    rate_limit: int = 30
    delay: float = 0.0
    proxy: Optional[str] = None

    # output
    verbose: bool = False
    silent: bool = False

    model_config = {"arbitrary_types_allowed": True}

    @field_validator("targets")
    @classmethod
    def targets_not_empty(cls, v: list[str]) -> list[str]:
        return [t.strip().lower() for t in v if t.strip()]
