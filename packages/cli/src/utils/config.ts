import { cosmiconfig } from "cosmiconfig";

export interface VibeCheckConfig {
  /** Glob patterns to exclude from scanning */
  exclude?: string[];
  /** Enable/disable AI analysis (requires ANTHROPIC_API_KEY) */
  ai?: boolean;
  /** Severity threshold to report: only show findings at or above this level */
  severity?: "critical" | "high" | "medium" | "low" | "info";
  /** Custom rules to disable by ID */
  disableRules?: string[];
}

const defaults: VibeCheckConfig = {
  exclude: [],
  ai: true,
  severity: "low",
  disableRules: [],
};

export async function loadConfig(
  directory: string,
): Promise<VibeCheckConfig> {
  const explorer = cosmiconfig("vibecheck");

  try {
    const result = await explorer.search(directory);
    if (result && result.config) {
      return { ...defaults, ...result.config };
    }
  } catch {
    // Config loading failed, use defaults
  }

  return defaults;
}
