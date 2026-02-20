#!/usr/bin/env bun
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { formatPrettyOutput } from "./output";
import { ScanResult, Severity } from "./types";

interface Args {
  apiUrl: string;
  apiKey: string;
  openrouterApiKey?: string;
  input?: string;
  base?: string;
  head?: string;
  staged: boolean;
  pack?: string;
  failOn?: Severity | "none";
  llmMode: "off" | "auto" | "always";
  llmModel?: string;
  format: "pretty" | "json";
  help: boolean;
}

interface ApiResponse extends ScanResult {
  policy: {
    id: string;
    name: string;
    failOn: Severity | "none";
  };
  shouldBlock: boolean;
  deterministicSummary?: {
    total: number;
    high: number;
    medium: number;
    low: number;
  };
  advisorySummary?: {
    total: number;
    high: number;
    medium: number;
    low: number;
  };
  llm?: {
    mode: string;
    attempted: boolean;
    enabled: boolean;
    model?: string | null;
    message?: string | null;
    findingsAdded: number;
  };
  error?: string;
}

async function main(): Promise<void> {
  const args = parseArgs(Bun.argv.slice(2));

  if (args.help) {
    printHelp();
    return;
  }

  const diff = await resolveDiffInput(args);
  const endpoint = `${args.apiUrl.replace(/\/$/, "")}/api/scan`;

  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": args.apiKey,
      ...(args.openrouterApiKey
        ? { "x-openrouter-api-key": args.openrouterApiKey }
        : {}),
    },
    body: JSON.stringify({
      diff,
      packId: args.pack,
      failOn: args.failOn,
      llm: {
        mode: args.llmMode,
        model: args.llmModel,
      },
    }),
  });

  const body = (await response.json()) as ApiResponse;

  if (!response.ok) {
    const message = body?.error || `HTTP ${response.status}`;
    throw new Error(`ThreatLens API error: ${message}`);
  }

  if (args.format === "json") {
    console.log(JSON.stringify(body, null, 2));
  } else {
    console.log(
      formatPrettyOutput({
        findings: body.findings,
        summary: body.summary,
      }),
    );
    console.log(`Policy pack: ${body.policy.id} (fail-on=${body.policy.failOn})`);
    console.log(
      `Deterministic summary: high=${body.deterministicSummary?.high ?? 0}, medium=${body.deterministicSummary?.medium ?? 0}, low=${body.deterministicSummary?.low ?? 0}`,
    );
    console.log(
      `LLM advisory: mode=${body.llm?.mode ?? "off"}, attempted=${Boolean(body.llm?.attempted)}, added=${body.llm?.findingsAdded ?? 0}${body.llm?.model ? `, model=${body.llm.model}` : ""}`,
    );
    if (body.llm?.message) {
      console.log(`LLM note: ${body.llm.message}`);
    }
  }

  if (body.shouldBlock) {
    process.exitCode = 1;
  }
}

function parseArgs(raw: string[]): Args {
  const requestedHelp = raw.includes("--help") || raw.includes("-h");
  const apiUrl = process.env.THREATLENS_API_URL || "https://threatlens.werz.xyz";
  const apiKey = process.env.THREATLENS_API_KEY || "";

  const args: Args = {
    apiUrl,
    apiKey,
    openrouterApiKey: process.env.OPENROUTER_API_KEY,
    staged: false,
    llmMode: "auto",
    format: "pretty",
    help: false,
  };

  for (let i = 0; i < raw.length; i += 1) {
    const arg = raw[i];

    if (arg === "--help" || arg === "-h") {
      args.help = true;
      continue;
    }

    if (arg === "--api-url") {
      const value = raw[i + 1];
      if (!value) {
        throw new Error("--api-url requires a value");
      }
      args.apiUrl = value;
      i += 1;
      continue;
    }

    if (arg === "--api-key") {
      const value = raw[i + 1];
      if (!value) {
        throw new Error("--api-key requires a value");
      }
      args.apiKey = value;
      i += 1;
      continue;
    }

    if (arg === "--openrouter-api-key") {
      const value = raw[i + 1];
      if (!value) {
        throw new Error("--openrouter-api-key requires a value");
      }
      args.openrouterApiKey = value;
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

    if (arg === "--staged") {
      args.staged = true;
      continue;
    }

    if (arg === "--pack") {
      const value = raw[i + 1];
      if (!value) {
        throw new Error("--pack requires a value");
      }
      args.pack = value;
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
        throw new Error("--llm-model requires a value");
      }
      args.llmModel = value;
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

    throw new Error(`Unknown argument: ${arg}`);
  }

  if (args.head && !args.base) {
    throw new Error("--head can only be used together with --base");
  }

  if (args.input && (args.base || args.head || args.staged)) {
    throw new Error("--input cannot be combined with --staged/--base/--head");
  }

  if (!args.help && !requestedHelp && !args.apiKey) {
    throw new Error("THREATLENS_API_KEY is required");
  }

  return args;
}

async function resolveDiffInput(args: Args): Promise<string> {
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
  console.log(`ThreatLens private client

Usage:
  bun run src/private-client.ts [--staged] [--pack <id>] [--llm off|auto|always]
  bun run src/private-client.ts --base <ref> [--head <ref>] [options]
  bun run src/private-client.ts --input <diff-file> [options]

Required auth:
  THREATLENS_API_KEY env var, or --api-key

Options:
  --api-url <url>            ThreatLens base URL (default: THREATLENS_API_URL or https://threatlens.werz.xyz)
  --api-key <key>            ThreatLens API key for x-api-key auth
  --openrouter-api-key <key> Optional OpenRouter key sent as x-openrouter-api-key
  --staged                   Scan staged changes
  --base <ref>               Diff from base ref
  --head <ref>               Optional head ref (with --base)
  --input <file>             Diff file input
  --pack <id>                Policy pack id
  --fail-on <level>          none|low|medium|high
  --llm <mode>               off|auto|always (default: auto)
  --llm-model <id>           OpenRouter model id override
  --format <mode>            pretty|json
  -h, --help                 Show help`);
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`ThreatLens private client error: ${message}`);
  process.exit(2);
});
