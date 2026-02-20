import { ScanResult } from "./types";

export function formatPrettyOutput(result: ScanResult): string {
  if (result.findings.length === 0) {
    return "No risky patterns found in added lines.";
  }

  const lines: string[] = [];
  lines.push("ThreatLens findings");
  lines.push("");

  for (const finding of result.findings) {
    lines.push(
      `[${finding.severity.toUpperCase()}] ${finding.title} (${finding.ruleId})`,
    );
    lines.push(`  at ${finding.filePath}:${finding.line}`);
    lines.push(`  ${finding.description}`);
    lines.push(`  > ${finding.evidence}`);
    lines.push("");
  }

  lines.push(
    `Summary: total=${result.summary.total}, high=${result.summary.high}, medium=${result.summary.medium}, low=${result.summary.low}`,
  );

  return lines.join("\n");
}
