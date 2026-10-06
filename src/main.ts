import { run } from "./cli";
import { EXIT } from "./errors";

try {
  process.exitCode = await run(process.argv.slice(2), {
    stdout: (text) => process.stdout.write(text),
    stderr: (text) => process.stderr.write(text),
    env: process.env,
    fetch: (input, init) => fetch(input, init),
    cwd: process.cwd(),
  });
} catch (error) {
  process.stderr.write(
    `cra: unexpected error: ${error instanceof Error ? (error.stack ?? error.message) : String(error)}\n`,
  );
  process.exitCode = EXIT.usage;
}
