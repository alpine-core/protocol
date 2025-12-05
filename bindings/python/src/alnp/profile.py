import hashlib
from dataclasses import dataclass


StreamIntent = str


@dataclass(frozen=True)
class CompiledStreamProfile:
    intent: StreamIntent
    latency_weight: int
    resilience_weight: int
    config_id: str


class StreamProfile:
    """Declarative stream-behavior profile used by ALPINE SDK helpers."""

    def __init__(self, intent: StreamIntent, latency_weight: int, resilience_weight: int) -> None:
        self.intent = intent
        self.latency_weight = latency_weight
        self.resilience_weight = resilience_weight

    @staticmethod
    def auto() -> "StreamProfile":
        return StreamProfile("auto", 50, 50)

    @staticmethod
    def realtime() -> "StreamProfile":
        return StreamProfile("realtime", 80, 20)

    @staticmethod
    def install() -> "StreamProfile":
        return StreamProfile("install", 25, 75)

    def compile(self) -> CompiledStreamProfile:
        """Validate weights and produce a deterministic config ID."""
        if self.latency_weight > 100:
            raise ValueError("latency weight must be between 0 and 100 inclusive")
        if self.resilience_weight > 100:
            raise ValueError("resilience weight must be between 0 and 100 inclusive")
        if self.latency_weight == 0 and self.resilience_weight == 0:
            raise ValueError("latency and resilience weights cannot both be zero")

        hasher = hashlib.sha256()
        hasher.update(f"{self.intent}:{self.latency_weight}:{self.resilience_weight}".encode("utf-8"))
        return CompiledStreamProfile(
            intent=self.intent,
            latency_weight=self.latency_weight,
            resilience_weight=self.resilience_weight,
            config_id=hasher.hexdigest(),
        )
