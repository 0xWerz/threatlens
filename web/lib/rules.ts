import { AddedLine, Rule } from "./types";

function nearby(
  linesInFile: AddedLine[],
  index: number,
  distance: number,
): string[] {
  const start = Math.max(0, index - distance);
  const end = Math.min(linesInFile.length - 1, index + distance);

  const result: string[] = [];
  for (let i = start; i <= end; i += 1) {
    result.push(linesInFile[i].text);
  }
  return result;
}

export const rules: Rule[] = [
  {
    id: "auth-bypass-toggle",
    title: "Auth checks look bypassed or disabled",
    severity: "high",
    description:
      "Code appears to disable auth or permission checks. This is a common source of privilege escalation.",
    match: (line) => {
      const pattern =
        /\b(auth|authorization|permission|rbac|acl)\b.{0,40}\b(disabled?|off|false|bypass|skip)\b|\b(disable|bypass|skip)\w*\b.{0,40}\b(auth|authorization|permission|rbac|acl)\b/i;
      return pattern.test(line.text) ? line.text.trim() : null;
    },
  },
  {
    id: "hardcoded-secret",
    title: "Possible hardcoded secret",
    severity: "high",
    description:
      "A literal token/password/secret was committed in code. Move this to a secret manager or env var.",
    match: (line) => {
      const pattern =
        /\b(api[_-]?key|secret|token|password|passwd|private[_-]?key)\b\s*[:=]\s*["'][^"']{8,}["']/i;
      return pattern.test(line.text) ? line.text.trim() : null;
    },
  },
  {
    id: "tls-verification-disabled",
    title: "TLS verification looks disabled",
    severity: "high",
    description:
      "TLS verification appears disabled. This can expose traffic to MITM attacks.",
    match: (line) => {
      const pattern =
        /\b(rejectUnauthorized|ssl_verify|insecureSkipVerify|verify|checkServerIdentity)\b\s*[:=]\s*(false|0|null)/i;
      return pattern.test(line.text) ? line.text.trim() : null;
    },
  },
  {
    id: "cors-wildcard-credentials",
    title: "Wildcard CORS origin with credentials",
    severity: "high",
    description:
      "Using origin '*' with credentials enabled can leak authenticated data cross-site.",
    match: (line, context) => {
      const window = nearby(context.linesInFile, context.indexInFile, 5).join("\n");
      const hasWildcardOrigin =
        /origin\s*:\s*["'`]\*["'`]/i.test(window) ||
        /Access-Control-Allow-Origin\s*[:=]\s*["'`]\*["'`]/i.test(window);
      const hasCredentials =
        /credentials\s*:\s*true/i.test(window) ||
        /Access-Control-Allow-Credentials\s*[:=]\s*["'`]true["'`]/i.test(window);

      return hasWildcardOrigin && hasCredentials ? line.text.trim() : null;
    },
  },
  {
    id: "open-redirect",
    title: "Potential open redirect",
    severity: "medium",
    description:
      "Redirect target appears user-controlled. Validate against an allowlist before redirecting.",
    match: (line) => {
      const pattern =
        /\b(redirect|location|res\.redirect|window\.location)\b.{0,50}\b(req\.(query|params|body)|next|returnTo|redirectUrl|url)\b/i;
      return pattern.test(line.text) ? line.text.trim() : null;
    },
  },
  {
    id: "ssrf-user-url",
    title: "Potential SSRF from user-controlled URL",
    severity: "high",
    description:
      "Outgoing request appears to use user input directly. Add URL validation and network egress controls.",
    match: (line) => {
      const pattern =
        /\b(fetch|axios\.(get|post|request)|axios|http\.get|https\.get|got|request)\b.{0,60}\b(req\.(query|params|body)|url|target|endpoint)\b/i;
      return pattern.test(line.text) ? line.text.trim() : null;
    },
  },
  {
    id: "command-exec-user-input",
    title: "Potential command injection",
    severity: "high",
    description:
      "Command execution appears to interpolate user input. Use safe APIs and strict argument handling.",
    match: (line) => {
      const pattern =
        /\b(exec|execSync|spawn|spawnSync)\b.{0,120}(req\.(query|params|body)|\$\{.*req\.)/i;
      return pattern.test(line.text) ? line.text.trim() : null;
    },
  },
  {
    id: "jwt-none-alg",
    title: "JWT algorithm set to none",
    severity: "high",
    description:
      "Accepting JWT alg=none breaks signature validation and can allow forged tokens.",
    match: (line) => {
      const pattern = /\balg\b\s*[:=]\s*["']none["']/i;
      return pattern.test(line.text) ? line.text.trim() : null;
    },
  },
];
