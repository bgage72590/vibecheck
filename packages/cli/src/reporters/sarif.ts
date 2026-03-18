import type { Finding, ScanResult, Severity } from "../types.js";

const SEVERITY_TO_SARIF: Record<Severity, string> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "none",
};

const SEVERITY_TO_LEVEL: Record<Severity, number> = {
  critical: 10.0,
  high: 8.0,
  medium: 5.0,
  low: 3.0,
  info: 1.0,
};

interface SarifOutput {
  $schema: string;
  version: string;
  runs: Array<{
    tool: {
      driver: {
        name: string;
        version: string;
        informationUri: string;
        rules: Array<{
          id: string;
          shortDescription: { text: string };
          fullDescription: { text: string };
          defaultConfiguration: { level: string };
          properties: { security_severity: string; tags: string[] };
        }>;
      };
    };
    results: Array<{
      ruleId: string;
      ruleIndex: number;
      level: string;
      message: { text: string };
      locations: Array<{
        physicalLocation: {
          artifactLocation: { uri: string };
          region: {
            startLine: number;
            startColumn?: number;
          };
        };
      }>;
      fixes?: Array<{
        description: { text: string };
      }>;
    }>;
  }>;
}

export function renderSarifReport(result: ScanResult): void {
  // Collect unique rules
  const ruleMap = new Map<string, Finding>();
  for (const f of result.findings) {
    if (!ruleMap.has(f.rule)) {
      ruleMap.set(f.rule, f);
    }
  }

  const rules = Array.from(ruleMap.entries()).map(([id, f]) => ({
    id,
    shortDescription: { text: f.title },
    fullDescription: { text: f.description },
    defaultConfiguration: { level: SEVERITY_TO_SARIF[f.severity] },
    properties: {
      security_severity: SEVERITY_TO_LEVEL[f.severity].toFixed(1),
      tags: ["security", f.category.toLowerCase().replace(/\s+/g, "-")],
    },
  }));

  const ruleIndex = new Map(rules.map((r, i) => [r.id, i]));

  const sarif: SarifOutput = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "vibecheck",
            version: "0.1.0",
            informationUri: "https://github.com/vibecheck/vibecheck",
            rules,
          },
        },
        results: result.findings.map((f) => {
          const entry: SarifOutput["runs"][0]["results"][0] = {
            ruleId: f.rule,
            ruleIndex: ruleIndex.get(f.rule) ?? 0,
            level: SEVERITY_TO_SARIF[f.severity],
            message: {
              text: `${f.title}: ${f.description}`,
            },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: f.file },
                  region: {
                    startLine: f.line,
                    ...(f.column ? { startColumn: f.column } : {}),
                  },
                },
              },
            ],
          };

          if (f.fix) {
            entry.fixes = [{ description: { text: f.fix } }];
          }

          return entry;
        }),
      },
    ],
  };

  console.log(JSON.stringify(sarif, null, 2));
}
