import { parseArgs } from "node:util";
import { clockCommand, initCommand, scopeCommand } from "./commands/basic";
import { allCommand, docsCommand, sbomCommand, scanCommand } from "./commands/pipeline";
import { publishCommand } from "./commands/publish";
import { FAIL_ON } from "./config";
import { CliError, ConfigError, EXIT, UsageError } from "./errors";
import { isOneOf } from "./guards";
import type { GlobalOptions, Io } from "./project";
import { CLI_VERSION } from "./version";

const COMMANDS: Record<string, { summary: string; options: string[]; usage: string }> = {
  init: {
    summary: "Write a commented cra.yml template",
    options: ["force"],
    usage: "cra init [--force]",
  },
  scope: {
    summary: "Scope verdict, product class, conformity route and obligations",
    options: [],
    usage: "cra scope [--json]",
  },
  sbom: {
    summary: "Generate a CycloneDX 1.6 SBOM (syft if on PATH, else lockfiles)",
    options: ["out"],
    usage: "cra sbom [--out <file>|-]",
  },
  scan: {
    summary: "Check the SBOM against OSV.dev and the CISA KEV catalog",
    options: ["sbom"],
    usage: "cra scan [--sbom <cyclonedx.json>] [--fail-on <level>]",
  },
  docs: {
    summary: "Write the compliance records into output.dir",
    options: [],
    usage: "cra docs",
  },
  all: {
    summary: "scope + sbom + scan + docs in one run, for CI",
    options: ["summary", "outputs"],
    usage: "cra all [--summary <file>] [--outputs <file>]",
  },
  publish: {
    summary:
      "Archive this release with the hosted ReleaseKeep service (token in RELEASEKEEP_TOKEN)",
    options: ["to", "artifact"],
    usage: "cra publish [--to <ReleaseKeep address>] [--artifact <file>]...",
  },
  clock: {
    summary: "Art. 14 reporting deadlines and their state",
    options: ["kind", "aware", "fixed", "notified", "warned"],
    usage:
      "cra clock --kind exploited_vulnerability|severe_incident --aware <ISO> [--fixed <ISO>] [--notified <ISO>] [--warned <ISO>]",
  },
};

const OPTIONS = {
  config: { type: "string" },
  cwd: { type: "string" },
  offline: { type: "boolean" },
  json: { type: "boolean" },
  quiet: { type: "boolean" },
  now: { type: "string" },
  version: { type: "string" },
  "print-version": { type: "boolean" },
  "fail-on": { type: "string" },
  help: { type: "boolean", short: "h" },
  force: { type: "boolean" },
  out: { type: "string" },
  sbom: { type: "string" },
  summary: { type: "string" },
  outputs: { type: "string" },
  kind: { type: "string" },
  aware: { type: "string" },
  fixed: { type: "string" },
  notified: { type: "string" },
  warned: { type: "string" },
  to: { type: "string" },
  artifact: { type: "string", multiple: true },
} as const;

const GLOBAL = new Set([
  "config",
  "cwd",
  "offline",
  "json",
  "quiet",
  "now",
  "version",
  "print-version",
  "fail-on",
  "help",
]);

export const HELP = `cra ${CLI_VERSION} - Cyber Resilience Act (EU 2024/2847) records for installed and distributed software

Usage: cra <command> [options]

Commands:
${Object.entries(COMMANDS)
  .map(([name, c]) => `  ${name.padEnd(9)}${c.summary}`)
  .join("\n")}

Options:
  --config <path>     cra.yml to use (default: cra.yml in the project directory)
  --cwd <dir>         project directory (default: current directory)
  --version <v>       product version for this run (default: product.version, else the git tag)
  --fail-on <level>   override scan.failOn: kev, critical, high or none
  --offline           no network: use cached OSV and KEV data from .cra-cache/ only
  --now <ISO time>    run as if it were this moment, for reproducible output
  --json              machine-readable output on stdout
  --quiet             print errors only
  -h, --help          help for cra or a command
  --version           (without a command) print the cra version

Exit codes: 0 ok, 1 usage or configuration error, 2 findings at or above scan.failOn,
            3 OSV, KEV or the ReleaseKeep service unreachable.

The generated documents are templates the manufacturer completes and signs.
They are not legal advice and do not demonstrate conformity by themselves.
`;

/** `--version` alone prints the tool version; `--version <v>` sets the product version. */
function normalizeVersionFlag(argv: string[]): string[] {
  return argv.map((arg, i) => {
    const next = argv[i + 1];
    return arg === "--version" && (next === undefined || next.startsWith("-"))
      ? "--print-version"
      : arg;
  });
}

function parseArgv(argv: string[]) {
  try {
    return parseArgs({
      args: normalizeVersionFlag(argv),
      options: OPTIONS,
      allowPositionals: true,
      strict: true,
    });
  } catch (error) {
    throw new UsageError(
      `${error instanceof Error ? error.message : String(error)}\nRun \`cra --help\` for usage.`,
    );
  }
}

export async function run(argv: string[], io: Io): Promise<number> {
  try {
    return await dispatch(argv, io);
  } catch (error) {
    if (error instanceof CliError) {
      io.stderr(`${error instanceof ConfigError ? "" : "error: "}${error.message}\n`);
      return error.exitCode;
    }
    throw error;
  }
}

async function dispatch(argv: string[], io: Io): Promise<number> {
  const { values, positionals } = parseArgv(argv);
  const [command, ...extra] = positionals;

  if (values["print-version"]) {
    io.stdout(`${CLI_VERSION}\n`);
    return EXIT.ok;
  }
  if (command === undefined || command === "help") {
    io.stdout(HELP);
    return command === undefined && !values.help ? EXIT.usage : EXIT.ok;
  }
  const spec = COMMANDS[command];
  if (!spec) {
    throw new UsageError(
      `unknown command "${command}"\nRun \`cra --help\` for the list of commands.`,
    );
  }
  if (values.help) {
    io.stdout(`${spec.summary}\n\nUsage: ${spec.usage}\n\nGlobal options: see \`cra --help\`.\n`);
    return EXIT.ok;
  }
  if (extra.length > 0) throw new UsageError(`unexpected argument: ${extra.join(" ")}`);
  for (const key of Object.keys(values)) {
    if (!GLOBAL.has(key) && !spec.options.includes(key)) {
      throw new UsageError(`--${key} does not apply to \`cra ${command}\` (usage: ${spec.usage})`);
    }
  }
  const failOn = values["fail-on"];
  if (failOn !== undefined && !isOneOf(FAIL_ON, failOn)) {
    throw new UsageError(`--fail-on must be one of: ${FAIL_ON.join(", ")}`);
  }
  let now: Date | undefined;
  if (values.now !== undefined) {
    now = new Date(values.now);
    if (!/^\d{4}-\d{2}-\d{2}/.test(values.now) || Number.isNaN(now.getTime())) {
      throw new UsageError(`--now expects an ISO 8601 time, got "${values.now}"`);
    }
  }
  const options: GlobalOptions = {
    config: values.config,
    cwd: values.cwd,
    offline: values.offline ?? false,
    json: values.json ?? false,
    quiet: values.quiet ?? false,
    now,
    productVersion: values.version,
    failOn,
  };

  switch (command) {
    case "init":
      return initCommand(options, io, values.force ?? false);
    case "scope":
      return scopeCommand(options, io);
    case "sbom":
      return sbomCommand(options, io, values.out);
    case "scan":
      return scanCommand(options, io, values.sbom);
    case "docs":
      return docsCommand(options, io);
    case "all":
      return allCommand(options, io, { summary: values.summary, outputs: values.outputs });
    case "publish":
      return publishCommand(options, io, { to: values.to, artifact: values.artifact });
    default:
      return clockCommand(options, io, values);
  }
}
