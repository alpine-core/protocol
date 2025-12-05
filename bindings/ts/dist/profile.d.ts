export type StreamIntent = "auto" | "realtime" | "install";
export declare class StreamProfile {
    private readonly intent;
    private readonly latencyWeight;
    private readonly resilienceWeight;
    private constructor();
    /**
     * Safe default balancing latency and smoothing.
     */
    static auto(): StreamProfile;
    /**
     * Low-latency profile that favors speed over smoothing.
     */
    static realtime(): StreamProfile;
    /**
     * Install/resilience profile that favors smoothness and robustness.
     */
    static install(): StreamProfile;
    /**
     * Returns a deterministic config ID derived from the normalized weights.
     */
    configId(): string;
    /**
     * Latency weight between 0 and 100.
     */
    getLatencyWeight(): number;
    /**
     * Resilience weight between 0 and 100.
     */
    getResilienceWeight(): number;
}
