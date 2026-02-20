import { NextRequest, NextResponse } from "next/server";
import { runLlmAdvisoryScan } from "@/lib/llm";
import { applyPolicy, PolicyOverrides, resolvePolicyPack } from "@/lib/packs";
import {
  scanDiff,
  severityMeetsThreshold,
  sortFindings,
  summarizeFindings,
} from "@/lib/scanner";
import { Finding, Severity } from "@/lib/types";

export const runtime = "nodejs";

const VALID_LEVELS = ["none", "low", "medium", "high"] as const;
const VALID_LLM_MODES = ["off", "auto", "always"] as const;
const MAX_DIFF_BYTES = 800_000;

interface ScanRequest {
  diff: string;
  packId?: string;
  failOn?: Severity | "none";
  overrides?: PolicyOverrides;
  llm?: {
    mode?: "off" | "auto" | "always";
    model?: string;
    timeoutMs?: number;
    maxFindings?: number;
  };
}

interface RequestAuthContext {
  hasValidApiKey: boolean;
  openrouterApiKey?: string;
}

class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

function json(data: unknown, status = 200): NextResponse {
  return NextResponse.json(data, {
    status,
    headers: {
      "cache-control": "no-store",
      "access-control-allow-origin": "*",
    },
  });
}

export async function OPTIONS(): Promise<NextResponse> {
  return new NextResponse(null, {
    status: 204,
    headers: {
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "POST, OPTIONS",
      "access-control-allow-headers": "content-type, x-api-key, x-openrouter-api-key",
    },
  });
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    const rawLength = Number.parseInt(request.headers.get("content-length") ?? "0", 10);
    if (Number.isFinite(rawLength) && rawLength > MAX_DIFF_BYTES + 100_000) {
      throw new ApiError(413, "Request body too large.");
    }

    const rawPayload = await parseJsonBody(request);
    const payload = validatePayload(rawPayload);

    const auth = resolveAuthContext(request);

    if (payload.overrides && !auth.hasValidApiKey) {
      throw new ApiError(
        403,
        "overrides are only available for authenticated requests",
      );
    }

    if (payload.llm?.mode && payload.llm.mode !== "off" && process.env.THREATLENS_API_KEY) {
      if (!auth.hasValidApiKey) {
        throw new ApiError(401, "Missing or invalid x-api-key for LLM mode.");
      }
    }

    const pack = resolvePolicyPack(payload.packId);
    const failOn = payload.failOn ?? pack.defaultFailOn;

    const baseResult = scanDiff(payload.diff);
    const deterministicFindings = applyPolicy(
      baseResult.findings,
      pack,
      payload.overrides,
      { respectEnabledRules: true },
    );

    const llmResult = await runLlmAdvisoryScan({
      diffText: payload.diff,
      deterministicFindings,
      options: {
        ...payload.llm,
        apiKey: auth.openrouterApiKey,
      },
    });

    const llmFindings = applyPolicy(
      llmResult.findings,
      pack,
      payload.overrides,
      { respectEnabledRules: false },
    );

    const mergedFindings = sortFindings(
      dedupeFindings([...deterministicFindings, ...llmFindings]),
    );

    const deterministicSummary = summarizeFindings(deterministicFindings);
    const llmSummary = summarizeFindings(llmFindings);
    const summary = summarizeFindings(mergedFindings);

    const shouldBlock = deterministicFindings.some((finding) =>
      severityMeetsThreshold(finding.severity, failOn),
    );

    return json({
      policy: {
        id: pack.id,
        name: pack.name,
        failOn,
      },
      shouldBlock,
      summary,
      deterministicSummary,
      advisorySummary: llmSummary,
      findings: mergedFindings,
      llm: {
        mode: llmResult.mode,
        attempted: llmResult.attempted,
        enabled: llmResult.enabled,
        model: llmResult.model ?? null,
        message: llmResult.reason ?? null,
        findingsAdded: llmFindings.length,
      },
    });
  } catch (error: unknown) {
    if (error instanceof ApiError) {
      return json({ error: error.message }, error.status);
    }

    const message = error instanceof Error ? error.message : "Unexpected error";
    return json({ error: message }, 500);
  }
}

async function parseJsonBody(request: NextRequest): Promise<unknown> {
  try {
    return await request.json();
  } catch {
    throw new ApiError(400, "Invalid JSON body");
  }
}

function validatePayload(raw: unknown): ScanRequest {
  if (!raw || typeof raw !== "object") {
    throw new ApiError(400, "Body must be a JSON object");
  }

  const payload = raw as Record<string, unknown>;

  if (typeof payload.diff !== "string" || payload.diff.trim().length === 0) {
    throw new ApiError(400, "Missing required field: diff (string)");
  }

  if (payload.diff.length > MAX_DIFF_BYTES) {
    throw new ApiError(413, "Diff too large. Max supported size is 800KB.");
  }

  const failOn = payload.failOn as Severity | "none" | undefined;
  if (
    failOn !== undefined &&
    (typeof failOn !== "string" ||
      !VALID_LEVELS.includes(failOn as (typeof VALID_LEVELS)[number]))
  ) {
    throw new ApiError(400, "failOn must be one of: none, low, medium, high");
  }

  const packId = payload.packId;
  if (packId !== undefined && typeof packId !== "string") {
    throw new ApiError(400, "packId must be a string");
  }

  const overrides = validateOverrides(payload.overrides);
  const llm = validateLlmOptions(payload.llm);

  return {
    diff: payload.diff,
    packId,
    failOn,
    overrides,
    llm,
  };
}

function validateOverrides(raw: unknown): PolicyOverrides | undefined {
  if (raw === undefined) {
    return undefined;
  }

  if (!raw || typeof raw !== "object") {
    throw new ApiError(400, "overrides must be an object");
  }

  const value = raw as Record<string, unknown>;

  const disableRules = value.disableRules;
  if (
    disableRules !== undefined &&
    (!Array.isArray(disableRules) || disableRules.some((item) => typeof item !== "string"))
  ) {
    throw new ApiError(400, "overrides.disableRules must be an array of strings");
  }

  const ignorePathsContaining = value.ignorePathsContaining;
  if (
    ignorePathsContaining !== undefined &&
    (!Array.isArray(ignorePathsContaining) ||
      ignorePathsContaining.some((item) => typeof item !== "string"))
  ) {
    throw new ApiError(
      400,
      "overrides.ignorePathsContaining must be an array of strings",
    );
  }

  const severityOverrides = value.severityOverrides;
  if (severityOverrides !== undefined) {
    if (!severityOverrides || typeof severityOverrides !== "object") {
      throw new ApiError(400, "overrides.severityOverrides must be an object");
    }

    for (const [key, level] of Object.entries(
      severityOverrides as Record<string, unknown>,
    )) {
      if (typeof key !== "string" || typeof level !== "string") {
        throw new ApiError(400, "Invalid overrides.severityOverrides entry");
      }

      if (!VALID_LEVELS.includes(level as (typeof VALID_LEVELS)[number]) || level === "none") {
        throw new ApiError(
          400,
          `Invalid severity override for '${key}'. Use low, medium, or high.`,
        );
      }
    }
  }

  return {
    disableRules: disableRules as string[] | undefined,
    ignorePathsContaining: ignorePathsContaining as string[] | undefined,
    severityOverrides: severityOverrides as Record<string, Severity> | undefined,
  };
}

function validateLlmOptions(raw: unknown): ScanRequest["llm"] {
  if (raw === undefined) {
    return undefined;
  }

  if (!raw || typeof raw !== "object") {
    throw new ApiError(400, "llm must be an object");
  }

  const value = raw as Record<string, unknown>;

  const mode = value.mode;
  if (
    mode !== undefined &&
    (typeof mode !== "string" ||
      !VALID_LLM_MODES.includes(mode as (typeof VALID_LLM_MODES)[number]))
  ) {
    throw new ApiError(400, "llm.mode must be one of: off, auto, always");
  }

  const model = value.model;
  if (model !== undefined && (typeof model !== "string" || model.length > 80)) {
    throw new ApiError(400, "llm.model must be a string up to 80 chars");
  }

  const timeoutMs = value.timeoutMs;
  if (
    timeoutMs !== undefined &&
    (typeof timeoutMs !== "number" || timeoutMs < 1000 || timeoutMs > 30000)
  ) {
    throw new ApiError(400, "llm.timeoutMs must be between 1000 and 30000");
  }

  const maxFindings = value.maxFindings;
  if (
    maxFindings !== undefined &&
    (typeof maxFindings !== "number" || maxFindings < 0 || maxFindings > 10)
  ) {
    throw new ApiError(400, "llm.maxFindings must be between 0 and 10");
  }

  return {
    mode: mode as "off" | "auto" | "always" | undefined,
    model: model as string | undefined,
    timeoutMs: timeoutMs as number | undefined,
    maxFindings: maxFindings as number | undefined,
  };
}

function resolveAuthContext(request: NextRequest): RequestAuthContext {
  const configuredApiKey = process.env.THREATLENS_API_KEY;
  if (!configuredApiKey) {
    return {
      hasValidApiKey: false,
    };
  }

  const callerKey = request.headers.get("x-api-key");
  const hasValidApiKey = callerKey === configuredApiKey;

  if (!hasValidApiKey) {
    return {
      hasValidApiKey: false,
    };
  }

  const rawOpenrouterKey = request.headers.get("x-openrouter-api-key");

  return {
    hasValidApiKey,
    openrouterApiKey:
      rawOpenrouterKey && rawOpenrouterKey.trim().length > 0
        ? rawOpenrouterKey.trim()
        : undefined,
  };
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
