export type Uuid = string;

export const ALPINE_VERSION = "1.0";

export enum MessageType {
  AlpineDiscover = "alpine_discover",
  AlpineDiscoverReply = "alpine_discover_reply",
  SessionInit = "session_init",
  SessionAck = "session_ack",
  SessionReady = "session_ready",
  SessionComplete = "session_complete",
  AlpineControl = "alpine_control",
  AlpineControlAck = "alpine_control_ack",
  AlpineFrame = "alpine_frame",
  Keepalive = "keepalive",
}

export enum ChannelFormat {
  U8 = "u8",
  U16 = "u16",
}

export enum ControlOp {
  GetInfo = "get_info",
  GetCaps = "get_caps",
  Identify = "identify",
  Restart = "restart",
  GetStatus = "get_status",
  SetConfig = "set_config",
  SetMode = "set_mode",
  TimeSync = "time_sync",
  Vendor = "vendor",
}

export enum ErrorCode {
  DiscoveryInvalidSignature = "DISCOVERY_INVALID_SIGNATURE",
  DiscoveryNonceMismatch = "DISCOVERY_NONCE_MISMATCH",
  DiscoveryUnsupportedVersion = "DISCOVERY_UNSUPPORTED_VERSION",
  HandshakeSignatureInvalid = "HANDSHAKE_SIGNATURE_INVALID",
  HandshakeKeyDerivationFailed = "HANDSHAKE_KEY_DERIVATION_FAILED",
  HandshakeTimeout = "HANDSHAKE_TIMEOUT",
  HandshakeReplay = "HANDSHAKE_REPLAY",
  SessionExpired = "SESSION_EXPIRED",
  SessionInvalidToken = "SESSION_INVALID_TOKEN",
  SessionMacMismatch = "SESSION_MAC_MISMATCH",
  ControlUnknownOp = "CONTROL_UNKNOWN_OP",
  ControlPayloadInvalid = "CONTROL_PAYLOAD_INVALID",
  ControlUnauthorized = "CONTROL_UNAUTHORIZED",
  StreamBadFormat = "STREAM_BAD_FORMAT",
  StreamTooLarge = "STREAM_TOO_LARGE",
  StreamUnsupportedChannelMode = "STREAM_UNSUPPORTED_CHANNEL_MODE",
}

export interface CapabilitySet {
  channel_formats: ChannelFormat[];
  max_channels: number;
  grouping_supported: boolean;
  streaming_supported: boolean;
  encryption_supported: boolean;
  vendor_extensions?: Record<string, unknown>;
}

export interface DeviceIdentity {
  device_id: string;
  manufacturer_id: string;
  model_id: string;
  hardware_rev: string;
  firmware_rev: string;
}

export interface DiscoveryRequest {
  type: MessageType.AlpineDiscover;
  version: string;
  client_nonce: Uint8Array;
  requested: string[];
}

export function buildDiscoveryRequest(requested: string[], clientNonce: Uint8Array): DiscoveryRequest {
  return {
    type: MessageType.AlpineDiscover,
    version: ALPINE_VERSION,
    client_nonce: clientNonce,
    requested,
  };
}

export interface DiscoveryReply {
  type: MessageType.AlpineDiscoverReply;
  alpine_version: string;
  device_id: string;
  manufacturer_id: string;
  model_id: string;
  hardware_rev: string;
  firmware_rev: string;
  mac: string;
  server_nonce: Uint8Array;
  capabilities: CapabilitySet;
  signature: Uint8Array;
}

export interface SessionInit {
  type: MessageType.SessionInit;
  controller_nonce: Uint8Array;
  controller_pubkey: Uint8Array;
  requested: CapabilitySet;
  session_id: Uuid;
}

export interface SessionAck {
  type: MessageType.SessionAck;
  device_nonce: Uint8Array;
  device_pubkey: Uint8Array;
  device_identity: DeviceIdentity;
  capabilities: CapabilitySet;
  signature: Uint8Array;
  session_id: Uuid;
}

export interface SessionReady {
  type: MessageType.SessionReady;
  session_id: Uuid;
  mac: Uint8Array;
}

export interface SessionComplete {
  type: MessageType.SessionComplete;
  session_id: Uuid;
  ok: boolean;
  error?: ErrorCode;
}

export interface ControlEnvelope {
  type: MessageType.AlpineControl;
  session_id: Uuid;
  seq: number;
  op: ControlOp;
  payload: unknown;
  mac: Uint8Array;
}

export function buildControlEnvelope(
  sessionId: Uuid,
  seq: number,
  op: ControlOp,
  payload: unknown,
  mac: Uint8Array,
): ControlEnvelope {
  return {
    type: MessageType.AlpineControl,
    session_id: sessionId,
    seq,
    op,
    payload,
    mac,
  };
}

export interface Acknowledge {
  type: MessageType.AlpineControlAck;
  session_id: Uuid;
  seq: number;
  ok: boolean;
  detail?: string;
  mac: Uint8Array;
}

export interface FrameEnvelope {
  type: MessageType.AlpineFrame;
  session_id: Uuid;
  timestamp_us: number;
  priority: number;
  channel_format: ChannelFormat;
  channels: number[];
  groups?: Record<string, number[]>;
  metadata?: Record<string, unknown>;
}

export function buildFrameEnvelope(
  sessionId: Uuid,
  timestampUs: number,
  priority: number,
  channelFormat: ChannelFormat,
  channels: number[],
  groups?: Record<string, number[]>,
  metadata?: Record<string, unknown>,
): FrameEnvelope {
  return {
    type: MessageType.AlpineFrame,
    session_id: sessionId,
    timestamp_us: timestampUs,
    priority,
    channel_format: channelFormat,
    channels,
    groups,
    metadata,
  };
}

export interface Keepalive {
  type: MessageType.Keepalive;
  session_id: Uuid;
  tick_ms: number;
}

export interface SessionState {
  state: "Init" | "Handshake" | "Authenticated" | "Ready" | "Streaming" | "Failed" | "Closed";
  reason?: string;
}

export * from "./profile";
