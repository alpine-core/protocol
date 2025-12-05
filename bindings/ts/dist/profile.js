"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.StreamProfile = void 0;
const crypto_1 = __importDefault(require("crypto"));
class StreamProfile {
    constructor(intent, latencyWeight, resilienceWeight) {
        this.intent = intent;
        this.latencyWeight = latencyWeight;
        this.resilienceWeight = resilienceWeight;
    }
    /**
     * Safe default balancing latency and smoothing.
     */
    static auto() {
        return new StreamProfile("auto", 50, 50);
    }
    /**
     * Low-latency profile that favors speed over smoothing.
     */
    static realtime() {
        return new StreamProfile("realtime", 80, 20);
    }
    /**
     * Install/resilience profile that favors smoothness and robustness.
     */
    static install() {
        return new StreamProfile("install", 25, 75);
    }
    /**
     * Returns a deterministic config ID derived from the normalized weights.
     */
    configId() {
        const hash = crypto_1.default.createHash("sha256");
        hash.update(`${this.intent}:${this.latencyWeight}:${this.resilienceWeight}`);
        return hash.digest("hex");
    }
    /**
     * Latency weight between 0 and 100.
     */
    getLatencyWeight() {
        return this.latencyWeight;
    }
    /**
     * Resilience weight between 0 and 100.
     */
    getResilienceWeight() {
        return this.resilienceWeight;
    }
}
exports.StreamProfile = StreamProfile;
