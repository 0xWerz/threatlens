import { Finding, Severity } from "./types";

export interface PathSuppression {
  contains: string;
  disableRules: string[];
}

export interface PolicyPack {
  id: string;
  name: string;
  description: string;
  defaultFailOn: Severity | "none";
  enabledRules?: string[];
  pathSuppressions?: PathSuppression[];
}

export interface PolicyOverrides {
  disableRules?: string[];
  severityOverrides?: Record<string, Severity>;
  ignorePathsContaining?: string[];
}

const POLICY_PACKS: PolicyPack[] = [
  {
    id: "startup-default",
    name: "Startup Default",
    description:
      "Balanced defaults for SaaS teams. Catch high-impact issues without blocking low-signal patterns.",
    defaultFailOn: "high",
    enabledRules: [
      "auth-bypass-toggle",
      "hardcoded-secret",
      "tls-verification-disabled",
      "cors-wildcard-credentials",
      "open-redirect",
      "ssrf-user-url",
      "command-exec-user-input",
      "jwt-none-alg",
    ],
    pathSuppressions: [
      {
        contains: "test/",
        disableRules: ["hardcoded-secret"],
      },
    ],
  },
  {
    id: "tenant-isolation",
    name: "Tenant Isolation Strict",
    description:
      "Stricter profile for multi-tenant products where auth and data boundary regressions are non-negotiable.",
    defaultFailOn: "medium",
    enabledRules: [
      "auth-bypass-toggle",
      "tls-verification-disabled",
      "cors-wildcard-credentials",
      "open-redirect",
      "ssrf-user-url",
      "command-exec-user-input",
      "jwt-none-alg",
      "hardcoded-secret",
    ],
    pathSuppressions: [
      {
        contains: "fixtures/",
        disableRules: ["hardcoded-secret"],
      },
      {
        contains: "examples/",
        disableRules: ["hardcoded-secret"],
      },
    ],
  },
];

export function listPolicyPacks(): PolicyPack[] {
  return POLICY_PACKS;
}

export function resolvePolicyPack(
  packId?: string,
): PolicyPack {
  if (!packId) {
    return POLICY_PACKS[0];
  }

  const found = POLICY_PACKS.find((pack) => pack.id === packId);
  if (!found) {
    throw new Error(
      `Unknown policy pack '${packId}'. Available packs: ${POLICY_PACKS.map((pack) => pack.id).join(", ")}`,
    );
  }

  return found;
}

export function applyPolicy(
  findings: Finding[],
  pack: PolicyPack,
  overrides?: PolicyOverrides,
  options?: { respectEnabledRules?: boolean },
): Finding[] {
  const disabledByOverride = new Set(overrides?.disableRules ?? []);
  const severityOverrides = overrides?.severityOverrides ?? {};
  const ignoredPathParts = overrides?.ignorePathsContaining ?? [];

  const respectEnabledRules = options?.respectEnabledRules ?? true;
  const allowedRuleIds = new Set(pack.enabledRules ?? findings.map((f) => f.ruleId));

  const filtered = findings
    .filter((finding) => {
      if (!respectEnabledRules) {
        return true;
      }
      return allowedRuleIds.has(finding.ruleId);
    })
    .filter((finding) => !disabledByOverride.has(finding.ruleId))
    .filter((finding) => {
      for (const pathPart of ignoredPathParts) {
        if (pathPart && finding.filePath.includes(pathPart)) {
          return false;
        }
      }
      return true;
    })
    .filter((finding) => {
      for (const suppression of pack.pathSuppressions ?? []) {
        if (!finding.filePath.includes(suppression.contains)) {
          continue;
        }

        if (suppression.disableRules.includes(finding.ruleId)) {
          return false;
        }
      }

      return true;
    })
    .map((finding) => {
      const nextSeverity = severityOverrides[finding.ruleId];
      if (!nextSeverity) {
        return finding;
      }

      return {
        ...finding,
        severity: nextSeverity,
      };
    });

  return filtered;
}
