import crypto from "crypto";

export type StreamIntent = "auto" | "realtime" | "install";

export class StreamProfile {
  private constructor(
    private readonly intent: StreamIntent,
    private readonly latencyWeight: number,
    private readonly resilienceWeight: number
  ) {}

  /**
   * Safe default balancing latency and smoothing.
   */
  public static auto(): StreamProfile {
    return new StreamProfile("auto", 50, 50);
  }

  /**
   * Low-latency profile that favors speed over smoothing.
   */
  public static realtime(): StreamProfile {
    return new StreamProfile("realtime", 80, 20);
  }

  /**
   * Install/resilience profile that favors smoothness and robustness.
   */
  public static install(): StreamProfile {
    return new StreamProfile("install", 25, 75);
  }

  /**
   * Returns a deterministic config ID derived from the normalized weights.
   */
  public configId(): string {
    const hash = crypto.createHash("sha256");
    hash.update(`${this.intent}:${this.latencyWeight}:${this.resilienceWeight}`);
    return hash.digest("hex");
  }

  /**
   * Latency weight between 0 and 100.
   */
  public getLatencyWeight(): number {
    return this.latencyWeight;
  }

  /**
   * Resilience weight between 0 and 100.
   */
  public getResilienceWeight(): number {
    return this.resilienceWeight;
  }
}
