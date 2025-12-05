"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ErrorCode = exports.ControlOp = exports.ChannelFormat = exports.MessageType = exports.ALPINE_VERSION = void 0;
exports.buildDiscoveryRequest = buildDiscoveryRequest;
exports.buildControlEnvelope = buildControlEnvelope;
exports.buildFrameEnvelope = buildFrameEnvelope;
exports.ALPINE_VERSION = "1.0";
var MessageType;
(function (MessageType) {
    MessageType["AlpineDiscover"] = "alpine_discover";
    MessageType["AlpineDiscoverReply"] = "alpine_discover_reply";
    MessageType["SessionInit"] = "session_init";
    MessageType["SessionAck"] = "session_ack";
    MessageType["SessionReady"] = "session_ready";
    MessageType["SessionComplete"] = "session_complete";
    MessageType["AlpineControl"] = "alpine_control";
    MessageType["AlpineControlAck"] = "alpine_control_ack";
    MessageType["AlpineFrame"] = "alpine_frame";
    MessageType["Keepalive"] = "keepalive";
})(MessageType || (exports.MessageType = MessageType = {}));
var ChannelFormat;
(function (ChannelFormat) {
    ChannelFormat["U8"] = "u8";
    ChannelFormat["U16"] = "u16";
})(ChannelFormat || (exports.ChannelFormat = ChannelFormat = {}));
var ControlOp;
(function (ControlOp) {
    ControlOp["GetInfo"] = "get_info";
    ControlOp["GetCaps"] = "get_caps";
    ControlOp["Identify"] = "identify";
    ControlOp["Restart"] = "restart";
    ControlOp["GetStatus"] = "get_status";
    ControlOp["SetConfig"] = "set_config";
    ControlOp["SetMode"] = "set_mode";
    ControlOp["TimeSync"] = "time_sync";
    ControlOp["Vendor"] = "vendor";
})(ControlOp || (exports.ControlOp = ControlOp = {}));
var ErrorCode;
(function (ErrorCode) {
    ErrorCode["DiscoveryInvalidSignature"] = "DISCOVERY_INVALID_SIGNATURE";
    ErrorCode["DiscoveryNonceMismatch"] = "DISCOVERY_NONCE_MISMATCH";
    ErrorCode["DiscoveryUnsupportedVersion"] = "DISCOVERY_UNSUPPORTED_VERSION";
    ErrorCode["HandshakeSignatureInvalid"] = "HANDSHAKE_SIGNATURE_INVALID";
    ErrorCode["HandshakeKeyDerivationFailed"] = "HANDSHAKE_KEY_DERIVATION_FAILED";
    ErrorCode["HandshakeTimeout"] = "HANDSHAKE_TIMEOUT";
    ErrorCode["HandshakeReplay"] = "HANDSHAKE_REPLAY";
    ErrorCode["SessionExpired"] = "SESSION_EXPIRED";
    ErrorCode["SessionInvalidToken"] = "SESSION_INVALID_TOKEN";
    ErrorCode["SessionMacMismatch"] = "SESSION_MAC_MISMATCH";
    ErrorCode["ControlUnknownOp"] = "CONTROL_UNKNOWN_OP";
    ErrorCode["ControlPayloadInvalid"] = "CONTROL_PAYLOAD_INVALID";
    ErrorCode["ControlUnauthorized"] = "CONTROL_UNAUTHORIZED";
    ErrorCode["StreamBadFormat"] = "STREAM_BAD_FORMAT";
    ErrorCode["StreamTooLarge"] = "STREAM_TOO_LARGE";
    ErrorCode["StreamUnsupportedChannelMode"] = "STREAM_UNSUPPORTED_CHANNEL_MODE";
})(ErrorCode || (exports.ErrorCode = ErrorCode = {}));
function buildDiscoveryRequest(requested, clientNonce) {
    return {
        type: MessageType.AlpineDiscover,
        version: exports.ALPINE_VERSION,
        client_nonce: clientNonce,
        requested,
    };
}
function buildControlEnvelope(sessionId, seq, op, payload, mac) {
    return {
        type: MessageType.AlpineControl,
        session_id: sessionId,
        seq,
        op,
        payload,
        mac,
    };
}
function buildFrameEnvelope(sessionId, timestampUs, priority, channelFormat, channels, groups, metadata) {
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
__exportStar(require("./profile"), exports);
