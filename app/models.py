from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

@dataclass
class ParsedConfig:
    format_name: str
    data: Any
    source_name: str
    decrypted: bool = True
    warnings: list[str] = field(default_factory=list)

@dataclass
class NormalizedConfig:
    protocol: str
    address: str
    port: int
    uuid: str | None = None
    password: str | None = None
    remark: str | None = None
    network: str | None = None
    security: str | None = None
    path: str | None = None
    host: str | None = None
    sni: str | None = None
    alpn: list[str] = field(default_factory=list)
    fingerprint: str | None = None
    flow: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)
