/** Process exit codes. CI scripts depend on these; never renumber. */
export const EXIT = {
  ok: 0,
  /** Bad flags, missing or invalid cra.yml, unreadable lockfile. */
  usage: 1,
  /** Vulnerability findings at or above `scan.failOn`. */
  findings: 2,
  /** OSV or CISA KEV unreachable while not running with --offline. */
  network: 3,
} as const;

export class CliError extends Error {
  constructor(
    message: string,
    readonly exitCode: number = EXIT.usage,
  ) {
    super(message);
    this.name = new.target.name;
  }
}

export class UsageError extends CliError {}

export class ConfigError extends CliError {
  constructor(
    readonly file: string,
    readonly problems: string[],
  ) {
    super(
      `${file} is not valid:\n${problems.map((p) => `  - ${p}`).join("\n")}\n` +
        "See the cra.yml reference in the README: https://github.com/override-tech/releasekeep#configuration-crayml",
    );
  }
}

export class NetworkError extends CliError {
  constructor(message: string) {
    super(`${message}\nRe-run with --offline to use cached vulnerability data only.`, EXIT.network);
  }
}

/** The `code` of a Node.js system error (ENOENT, EACCES...), if any. */
export function errnoCode(error: unknown): string | undefined {
  return error instanceof Error && "code" in error && typeof error.code === "string"
    ? error.code
    : undefined;
}
