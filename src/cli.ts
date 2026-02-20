#!/usr/bin/env bun
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { runLlmAdvisoryScan } from "./llm";
import { formatPrettyOutput } from "./output";
import { applyPolicy, listPolicyPacks, resolvePolicyPack } from "./packs";
import {
  scanDiff,
  severityMeetsThreshold,
  sortFindings,
  summarizeFindings,
} from "./scanner";
import { Finding, Severity } from "./types";

interface CliArgs {
  input?: string;
  format: "pretty" | "json";
  failOn?: Severity | "none";
  pack?: string;
  llmMode: "off" | "auto" | "always";
  llmModel?: string;
  staged: boolean;
  base?: string;
  head?: string;
  listPacks: boolean;
  help: boolean;
  version: boolean;
}

const VERSION = "0.2.0";

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

  if (args.listPacks) {
    for (const pack of listPolicyPacks()) {
      console.log(`${pack.id} - ${pack.name}`);
      console.log(`  ${pack.description}`);
      console.log(`  default fail-on: ${pack.defaultFailOn}`);
      console.log("");
    }
    return;
  }

  const diffText = await resolveDiffInput(args);
  const pack = resolvePolicyPack(args.pack);
  const baseResult = scanDiff(diffText);
  const deterministicFindings = applyPolicy(baseResult.findings, pack);

  const llmResult = await runLlmAdvisoryScan({
    diffText,
    deterministicFindings,
    options: {
      mode: args.llmMode,
      model: args.llmModel,
    },
  });

  const combinedFindings = sortFindings(
    dedupeFindings([...deterministicFindings, ...llmResult.findings]),
  );

  const result = {
    findings: combinedFindings,
    summary: summarizeFindings(combinedFindings),
  };

  const failOn = args.failOn ?? pack.defaultFailOn;

  if (args.format === "json") {
    console.log(JSON.stringify({ ...result, llm: llmResult }, null, 2));
  } else {
    console.log(formatPrettyOutput(result));
    console.log(`Policy pack: ${pack.id} (fail-on=${failOn})`);
    console.log(
      `LLM advisory: mode=${llmResult.mode}, attempted=${llmResult.attempted}, added=${llmResult.findings.length}${llmResult.model ? `, model=${llmResult.model}` : ""}`,
    );
    if (llmResult.reason) {
      console.log(`LLM note: ${llmResult.reason}`);
    }
  }

  const shouldFail = deterministicFindings.some((finding) =>
    severityMeetsThreshold(finding.severity, failOn),
  );

  if (shouldFail) {
    process.exitCode = 1;
  }
}

function parseArgs(raw: string[]): CliArgs {
  const args: CliArgs = {
    format: "pretty",
    llmMode: "off",
    staged: false,
    listPacks: false,
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

    if (arg === "--list-packs") {
      args.listPacks = true;
      continue;
    }

    if (arg === "--pack") {
      const value = raw[i + 1];
      if (!value) {
        throw new Error("--pack requires a policy pack id");
      }
      args.pack = value;
      i += 1;
      continue;
    }

    if (arg === "--llm") {
      const value = raw[i + 1];
      if (value !== "off" && value !== "auto" && value !== "always") {
        throw new Error("--llm must be one of: off, auto, always");
      }
      args.llmMode = value;
      i += 1;
      continue;
    }

    if (arg === "--llm-model") {
      const value = raw[i + 1];
      if (!value) {
        throw new Error("--llm-model requires a model id");
      }
      args.llmModel = value;
      i += 1;
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
  threatlens [--staged] [--pack <pack-id>] [--llm off|auto|always] [--llm-model <id>] [--format pretty|json] [--fail-on none|low|medium|high]
  threatlens --base <ref> [--head <ref>] [--pack <pack-id>] [--llm ...] [--format pretty|json] [--fail-on ...]
  threatlens --input <path-to-diff-file> [--pack <pack-id>] [--llm ...] [--format pretty|json] [--fail-on ...]
  threatlens --list-packs

Options:
  --staged           Scan staged changes (git diff --cached)
  --base <ref>       Scan diff from a base ref
  --head <ref>       Optional head ref (only with --base)
  --input <file>     Scan a diff from a file
  --pack <id>        Select policy pack (default: startup-default)
  --list-packs       Show available policy packs
  --llm <mode>       LLM advisory mode: off | auto | always (default: off)
  --llm-model <id>   Optional OpenRouter model id override
  --format <mode>    Output format: pretty | json (default: pretty)
  --fail-on <level>  Override pack fail threshold
  -h, --help         Show help
  -v, --version      Show version`);
}

function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const result: Finding[] = [];

  for (const finding of findings) {
    const key = `${finding.ruleId}:${finding.filePath}:${finding.line}:${finding.evidence}:${finding.source ?? "rule"}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    result.push(finding);
  }

  return result;
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`ThreatLens error: ${message}`);
  process.exit(2);
});
