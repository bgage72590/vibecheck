export interface ScanHistoryEntry {
  timestamp: string;
  grade: string;
  score: number;
  findingsCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  filesScanned: number;
}

const STORAGE_KEY = "vibecheck-scan-history";
const MAX_ENTRIES = 20;

export function saveScanResult(entry: ScanHistoryEntry): void {
  try {
    const history = getScanHistory();
    history.push(entry);
    if (history.length > MAX_ENTRIES) {
      history.splice(0, history.length - MAX_ENTRIES);
    }
    localStorage.setItem(STORAGE_KEY, JSON.stringify(history));
  } catch {
    // localStorage unavailable or full
  }
}

export function getScanHistory(): ScanHistoryEntry[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed;
  } catch {
    return [];
  }
}

export function clearScanHistory(): void {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    // ignore
  }
}
