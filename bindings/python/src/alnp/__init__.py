"""
Python bindings for ALPINE 1.0 message envelopes.

These helpers mirror the Rust types and make it straightforward to build CBOR-ready
maps for discovery, handshake, control, and streaming operations.
"""

from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional

ALPINE_VERSION = "1.0"

from .profile import CompiledStreamProfile, StreamProfile


@dataclass
class CapabilitySet:
    channel_formats: List[str]
    max_channels: int
    grouping_supported: bool
    streaming_supported: bool
    encryption_supported: bool
    vendor_extensions: Optional[Dict[str, Any]] = None


@dataclass
class DeviceIdentity:
    device_id: str
    manufacturer_id: str
    model_id: str
    hardware_rev: str
    firmware_rev: str


@dataclass
class DiscoveryRequest:
    type: str
    version: str
    client_nonce: bytes
    requested: List[str]

    @staticmethod
    def new(requested: List[str], client_nonce: bytes) -> "DiscoveryRequest":
        return DiscoveryRequest(
            type="alpine_discover",
            version=ALPINE_VERSION,
            client_nonce=client_nonce,
            requested=requested,
        )

    def to_map(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "version": self.version,
            "client_nonce": self.client_nonce,
            "requested": self.requested,
        }


@dataclass
class DiscoveryReply:
    type: str
    alpine_version: str
    device_id: str
    manufacturer_id: str
    model_id: str
    hardware_rev: str
    firmware_rev: str
    mac: str
    server_nonce: bytes
    capabilities: CapabilitySet
    signature: bytes

    def to_map(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["capabilities"] = asdict(self.capabilities)
        return payload


@dataclass
class ControlEnvelope:
    type: str
    session_id: str
    seq: int
    op: str
    payload: Dict[str, Any]
    mac: bytes

    def to_map(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FrameEnvelope:
    type: str
    session_id: str
    timestamp_us: int
    priority: int
    channel_format: str
    channels: List[int]
    groups: Optional[Dict[str, List[int]]] = None
    metadata: Optional[Dict[str, Any]] = None

    def to_map(self) -> Dict[str, Any]:
        return asdict(self)


def _to_cbor(map_obj: Dict[str, Any]) -> bytes:
    """
    Encode a mapping to CBOR if the cbor2 dependency is available.
    """
    try:
        import cbor2  # type: ignore
    except Exception as exc:  # pragma: no cover - optional dependency
        raise RuntimeError("cbor2 not installed; please `pip install cbor2`") from exc
    return cbor2.dumps(map_obj)


def encode_control(control: ControlEnvelope) -> bytes:
    return _to_cbor(control.to_map())


def encode_frame(frame: FrameEnvelope) -> bytes:
    return _to_cbor(frame.to_map())


def build_discovery_request(requested: List[str], client_nonce: bytes) -> DiscoveryRequest:
    return DiscoveryRequest(
        type="alpine_discover",
        version=ALPINE_VERSION,
        client_nonce=client_nonce,
        requested=requested,
    )


def build_control_envelope(
    session_id: str, seq: int, op: str, payload: Dict[str, Any], mac: bytes
) -> ControlEnvelope:
    return ControlEnvelope(
        type="alpine_control",
        session_id=session_id,
        seq=seq,
        op=op,
        payload=payload,
        mac=mac,
    )


def build_frame_envelope(
    session_id: str,
    timestamp_us: int,
    priority: int,
    channel_format: str,
    channels: List[int],
    groups: Optional[Dict[str, List[int]]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> FrameEnvelope:
    return FrameEnvelope(
        type="alpine_frame",
        session_id=session_id,
        timestamp_us=timestamp_us,
        priority=priority,
        channel_format=channel_format,
        channels=channels,
        groups=groups,
        metadata=metadata,
    )


__all__ = [
    "ALPINE_VERSION",
    "CapabilitySet",
    "DeviceIdentity",
    "DiscoveryRequest",
    "DiscoveryReply",
    "build_discovery_request",
    "ControlEnvelope",
    "FrameEnvelope",
    "build_control_envelope",
    "build_frame_envelope",
    "encode_control",
    "encode_frame",
    "StreamProfile",
    "CompiledStreamProfile",
]
