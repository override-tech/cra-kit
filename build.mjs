// Bundles the CLI and its dependencies into one ESM file so the GitHub Action
// and `npx` need nothing but Node.
import { chmod } from "node:fs/promises";
import { build } from "esbuild";

const outfile = "dist/cra.mjs";

await build({
  entryPoints: ["src/main.ts"],
  outfile,
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node22",
  legalComments: "none",
  banner: {
    // Some bundled CommonJS code calls require() for Node built-ins.
    js: [
      "#!/usr/bin/env node",
      'import { createRequire as __craCreateRequire } from "node:module";',
      "const require = __craCreateRequire(import.meta.url);",
    ].join("\n"),
  },
});
await chmod(outfile, 0o755);
