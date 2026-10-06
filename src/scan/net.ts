import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { errnoCode, NetworkError } from "../errors";
import { asRecord, asString } from "../guards";
import { CLI_VERSION } from "../version";

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

/** Vulnerability feeds are re-fetched after six hours; older copies serve --offline runs. */
export const CACHE_TTL_MS = 6 * 60 * 60 * 1000;
const REQUEST_TIMEOUT_MS = 30_000;
const ATTEMPTS = 3;

export interface NetOptions {
  fetch: FetchLike;
  /** Pause before retry n is n * retryDelayMs. */
  retryDelayMs: number;
}

/** GET or POST JSON with a timeout per attempt, retrying 429, 5xx and transport errors. */
export async function requestJson(net: NetOptions, url: string, body?: unknown): Promise<unknown> {
  let lastError = "";
  for (let attempt = 1; attempt <= ATTEMPTS; attempt++) {
    try {
      const response = await net.fetch(url, {
        method: body === undefined ? "GET" : "POST",
        headers: {
          accept: "application/json",
          "user-agent": `releasekeep-cra/${CLI_VERSION}`,
          ...(body === undefined ? {} : { "content-type": "application/json" }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (response.ok) return await response.json();
      lastError = `HTTP ${response.status}`;
      if (response.status !== 429 && response.status < 500) break;
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    }
    if (attempt < ATTEMPTS) await sleep(attempt * net.retryDelayMs);
  }
  throw new NetworkError(`Request to ${url} failed: ${lastError}`);
}

/** JSON files under .cra-cache/, each stamped with the time it was fetched. */
export class FeedCache {
  constructor(
    readonly dir: string,
    readonly now: Date,
  ) {}

  /** The cached payload (unvalidated; callers narrow it) and whether it is within the TTL. */
  async read(name: string): Promise<{ data: unknown; fresh: boolean } | null> {
    let text: string;
    try {
      text = await readFile(join(this.dir, name), "utf8");
    } catch (error) {
      if (errnoCode(error) === "ENOENT") return null;
      throw error;
    }
    let envelope: Record<string, unknown>;
    try {
      envelope = asRecord(JSON.parse(text));
    } catch {
      return null; // a torn or foreign file is treated as a miss
    }
    const fetchedAt = new Date(asString(envelope.fetchedAt) ?? "").getTime();
    if (Number.isNaN(fetchedAt)) return null;
    const age = this.now.getTime() - fetchedAt;
    return { data: envelope.data, fresh: age >= 0 && age < CACHE_TTL_MS };
  }

  async write(name: string, data: unknown): Promise<void> {
    const path = join(this.dir, name);
    await mkdir(dirname(path), { recursive: true });
    const temp = `${path}.${process.pid}.tmp`;
    await writeFile(temp, JSON.stringify({ fetchedAt: this.now.toISOString(), data }));
    await rename(temp, path);
  }
}
