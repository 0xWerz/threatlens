#!/usr/bin/env bun
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { formatPrettyOutput } from "./output";
import { scanDiff, severityMeetsThreshold } from "./scanner";
import { Severity } from "./types";

interface CliArgs {
  input?: string;
  format: "pretty" | "json";
  failOn: Severity | "none";
  staged: boolean;
  base?: string;
  head?: string;
  help: boolean;
  version: boolean;
}

const VERSION = "0.1.0";

async function main(): Promise<void> {
  const args = parseArgs(Bun.argv.slice(2));

  if (args.help) {
    printHelp();
    return;
  }

  if (args.version) {
    console.log(VERSION);
    return;
  }

  const diffText = await resolveDiffInput(args);
  const result = scanDiff(diffText);

  if (args.format === "json") {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(formatPrettyOutput(result));
  }

  const shouldFail = result.findings.some((finding) =>
    severityMeetsThreshold(finding.severity, args.failOn),
  );

  if (shouldFail) {
    process.exitCode = 1;
  }
}

function parseArgs(raw: string[]): CliArgs {
  const args: CliArgs = {
    format: "pretty",
    failOn: "medium",
    staged: false,
    help: false,
    version: false,
  };

  for (let i = 0; i < raw.length; i += 1) {
    const arg = raw[i];

    if (arg === "--help" || arg === "-h") {
      args.help = true;
      continue;
    }

    if (arg === "--version" || arg === "-v") {
      args.version = true;
      continue;
    }

    if (arg === "--staged") {
      args.staged = true;
      continue;
    }

    if (arg === "--input") {
      const value = raw[i + 1];
      if (!value) {
        throw new Error("--input requires a file path");
      }
      args.input = value;
      i += 1;
      continue;
    }

    if (arg === "--base") {
      const value = raw[i + 1];
      if (!value) {
        throw new Error("--base requires a git ref");
      }
      args.base = value;
      i += 1;
      continue;
    }

    if (arg === "--head") {
      const value = raw[i + 1];
      if (!value) {
        throw new Error("--head requires a git ref");
      }
      args.head = value;
      i += 1;
      continue;
    }

    if (arg === "--format") {
      const value = raw[i + 1];
      if (value !== "pretty" && value !== "json") {
        throw new Error("--format must be 'pretty' or 'json'");
      }
      args.format = value;
      i += 1;
      continue;
    }

    if (arg === "--fail-on") {
      const value = raw[i + 1];
      if (
        value !== "none" &&
        value !== "low" &&
        value !== "medium" &&
        value !== "high"
      ) {
        throw new Error("--fail-on must be one of: none, low, medium, high");
      }
      args.failOn = value;
      i += 1;
      continue;
    }

    throw new Error(`Unknown argument: ${arg}`);
  }

  if (args.head && !args.base) {
    throw new Error("--head can only be used together with --base");
  }

  if (args.input && (args.base || args.head || args.staged)) {
    throw new Error("--input cannot be combined with --staged/--base/--head");
  }

  return args;
}

async function resolveDiffInput(args: CliArgs): Promise<string> {
  if (args.input) {
    if (!existsSync(args.input)) {
      throw new Error(`Input file not found: ${args.input}`);
    }

    return readFile(args.input, "utf8");
  }

  if (args.base) {
    const refs = args.head ? [args.base, args.head] : [args.base];
    return runGitDiff(["--unified=3", ...refs]);
  }

  if (args.staged) {
    return runGitDiff(["--cached", "--unified=3"]);
  }

  const workingTreeDiff = await runGitDiff(["--unified=3"]);
  if (workingTreeDiff.trim()) {
    return workingTreeDiff;
  }

  return runGitDiff(["--cached", "--unified=3"]);
}

async function runGitDiff(extraArgs: string[]): Promise<string> {
  const proc = Bun.spawn(["git", "diff", ...extraArgs], {
    stdout: "pipe",
    stderr: "pipe",
  });

  const output = await new Response(proc.stdout).text();
  const error = await new Response(proc.stderr).text();
  const status = await proc.exited;

  if (status !== 0) {
    throw new Error(`git diff failed: ${error.trim() || "unknown error"}`);
  }

  return output;
}

function printHelp(): void {
  console.log(`ThreatLens ${VERSION}

Usage:
  threatlens [--staged] [--format pretty|json] [--fail-on none|low|medium|high]
  threatlens --base <ref> [--head <ref>] [--format pretty|json] [--fail-on ...]
  threatlens --input <path-to-diff-file> [--format pretty|json] [--fail-on ...]

Options:
  --staged           Scan staged changes (git diff --cached)
  --base <ref>       Scan diff from a base ref
  --head <ref>       Optional head ref (only with --base)
  --input <file>     Scan a diff from a file
  --format <mode>    Output format: pretty | json (default: pretty)
  --fail-on <level>  Exit non-zero when findings meet level (default: medium)
  -h, --help         Show help
  -v, --version      Show version`);
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`ThreatLens error: ${message}`);
  process.exit(2);
});
