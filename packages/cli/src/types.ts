export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  id: string;
  rule: string;
  severity: Severity;
  title: string;
  description: string;
  file: string;
  line: number;
  column?: number;
  snippet: string;
  fix?: string;
  fixCode?: { before: string; after: string };
  category: string;
  source: "custom" | "semgrep" | "gitleaks" | "ai";
  owasp?: string;
  cwe?: string;
}

export interface ScanResult {
  findings: Finding[];
  filesScanned: number;
  duration: number;
  timestamp: string;
  directory: string;
}

export interface ScanOptions {
  directory: string;
  aiAnalysis: boolean;
  format: "terminal" | "json" | "sarif";
  verbose: boolean;
  diff?: string | boolean;
}

export interface RuleMatch {
  rule: string;
  title: string;
  severity: Severity;
  category: string;
  file: string;
  line: number;
  column?: number;
  snippet: string;
  fix?: string;
}

export interface CustomRule {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  description: string;
  check: (content: string, filePath: string) => RuleMatch[];
}
