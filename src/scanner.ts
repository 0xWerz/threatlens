import { parseAddedLines } from "./diff";
import { rules } from "./rules";
import { Finding, ScanResult, Severity } from "./types";

const SEVERITY_ORDER: Record<Severity, number> = {
  high: 3,
  medium: 2,
  low: 1,
};

export function severityMeetsThreshold(
  severity: Severity,
  threshold: Severity | "none",
): boolean {
  if (threshold === "none") {
    return false;
  }

  return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[threshold];
}

export function scanDiff(diffText: string): ScanResult {
  const addedLines = parseAddedLines(diffText);
  const linesByFile = groupByFile(addedLines);
  const findings: Finding[] = [];

  for (const [filePath, lines] of linesByFile.entries()) {
    lines.forEach((line, index) => {
      for (const rule of rules) {
        const evidence = rule.match(line, {
          linesInFile: lines,
          indexInFile: index,
        });

        if (!evidence) {
          continue;
        }

        findings.push({
          ruleId: rule.id,
          title: rule.title,
          severity: rule.severity,
          description: rule.description,
          filePath,
          line: line.line,
          evidence,
        });
      }
    });
  }

  const deduped = dedupeFindings(findings);
  const sorted = deduped.sort((a, b) => {
    const severityDiff = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
    if (severityDiff !== 0) {
      return severityDiff;
    }

    const fileDiff = a.filePath.localeCompare(b.filePath);
    if (fileDiff !== 0) {
      return fileDiff;
    }

    return a.line - b.line;
  });

  return {
    findings: sorted,
    summary: {
      total: sorted.length,
      high: sorted.filter((f) => f.severity === "high").length,
      medium: sorted.filter((f) => f.severity === "medium").length,
      low: sorted.filter((f) => f.severity === "low").length,
    },
  };
}

function groupByFile(lines: ReturnType<typeof parseAddedLines>) {
  const result = new Map<string, ReturnType<typeof parseAddedLines>>();

  for (const line of lines) {
    const existing = result.get(line.filePath);
    if (existing) {
      existing.push(line);
    } else {
      result.set(line.filePath, [line]);
    }
  }

  return result;
}

function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const result: Finding[] = [];

  for (const finding of findings) {
    const key = `${finding.ruleId}:${finding.filePath}:${finding.line}:${finding.evidence}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    result.push(finding);
  }

  return result;
}
