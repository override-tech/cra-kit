import { execFileSync } from "node:child_process";

function git(cwd: string, args: string[]): string | null {
  try {
    return execFileSync("git", args, {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 10_000,
    }).trim();
  } catch {
    return null;
  }
}

/** "v1.4.0" or "app-v1.4.0" -> "1.4.0"; other tag names are used as they are. */
export function versionFromTag(tag: string): string {
  return /v?(\d+\.\d+.*)$/.exec(tag)?.[1] ?? tag;
}

/** The release tag being built: GitHub Actions' ref on tag builds, else an exact git tag on HEAD. */
export function tagVersion(cwd: string, env: Record<string, string | undefined>): string | null {
  if (env.GITHUB_REF_TYPE === "tag" && env.GITHUB_REF_NAME)
    return versionFromTag(env.GITHUB_REF_NAME);
  const tag = git(cwd, ["describe", "--tags", "--exact-match", "HEAD"]);
  return tag ? versionFromTag(tag) : null;
}

/** Committer date of HEAD, the closest thing to a release date that is stable per commit. */
export function headCommitDate(cwd: string): Date | null {
  const iso = git(cwd, ["log", "-1", "--format=%cI", "HEAD"]);
  const date = iso ? new Date(iso) : null;
  return date && !Number.isNaN(date.getTime()) ? date : null;
}

/** Full SHA of HEAD, if this is a git checkout. */
export function headCommit(cwd: string): string | null {
  const sha = git(cwd, ["rev-parse", "HEAD"]);
  return sha && /^[0-9a-f]{40}$/.test(sha) ? sha : null;
}
