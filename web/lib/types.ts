export type Severity = "low" | "medium" | "high";

export interface AddedLine {
  filePath: string;
  line: number;
  text: string;
}

export interface RuleContext {
  linesInFile: AddedLine[];
  indexInFile: number;
}

export interface Rule {
  id: string;
  title: string;
  severity: Severity;
  description: string;
  match: (line: AddedLine, context: RuleContext) => string | null;
}

export interface Finding {
  ruleId: string;
  title: string;
  severity: Severity;
  description: string;
  filePath: string;
  line: number;
  evidence: string;
  source?: "rule" | "llm";
  confidence?: number;
}

export interface ScanSummary {
  total: number;
  high: number;
  medium: number;
  low: number;
}

export interface ScanResult {
  findings: Finding[];
  summary: ScanSummary;
}
