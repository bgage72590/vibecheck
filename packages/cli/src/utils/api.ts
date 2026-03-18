import { readFileSync, writeFileSync, mkdirSync, existsSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

const CONFIG_DIR = join(homedir(), ".vibecheck");
const TOKEN_FILE = join(CONFIG_DIR, "token.json");

const API_BASE = process.env.VIBECHECK_API_URL ?? "https://api.vibecheck.dev";

if (API_BASE.startsWith("http://") && !API_BASE.includes("localhost") && !API_BASE.includes("127.0.0.1")) {
  console.warn("WARNING: API URL is not using HTTPS. This is insecure.");
}

interface TokenData {
  token: string;
  userId: string;
  email: string;
  expiresAt?: number;
}

export function getStoredToken(): TokenData | null {
  try {
    if (!existsSync(TOKEN_FILE)) return null;
    const data = JSON.parse(readFileSync(TOKEN_FILE, "utf-8"));
    if (data.expiresAt && Date.now() > data.expiresAt) {
      // Token expired
      unlinkSync(TOKEN_FILE);
      return null;
    }
    return data;
  } catch {
    return null;
  }
}

export function storeToken(data: TokenData): void {
  mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  writeFileSync(TOKEN_FILE, JSON.stringify(data, null, 2), { mode: 0o600 });
}

export function clearToken(): void {
  try {
    if (existsSync(TOKEN_FILE)) {
      unlinkSync(TOKEN_FILE);
    }
  } catch {
    // ignore
  }
}

export function isAuthenticated(): boolean {
  return getStoredToken() !== null;
}

async function apiRequest(
  path: string,
  options: RequestInit = {},
): Promise<Response> {
  const token = getStoredToken();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };

  if (token) {
    headers.Authorization = `Bearer ${token.token}`;
  }

  return fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });
}

export async function checkUsage(): Promise<{
  allowed: boolean;
  plan: string;
  remaining: number;
  limit: number;
}> {
  const token = getStoredToken();
  if (!token) {
    // Unauthenticated users get limited local scans
    return { allowed: true, plan: "anonymous", remaining: -1, limit: -1 };
  }

  try {
    const res = await apiRequest("/api/usage/check");
    if (!res.ok) {
      // API error — allow scan to proceed locally
      return { allowed: true, plan: "unknown", remaining: -1, limit: -1 };
    }
    return await res.json();
  } catch {
    // Network error — allow local scan
    return { allowed: true, plan: "offline", remaining: -1, limit: -1 };
  }
}

export async function incrementUsage(): Promise<void> {
  const token = getStoredToken();
  if (!token) return;

  try {
    await apiRequest("/api/usage/increment", { method: "POST" });
  } catch {
    // Silent fail — don't block scan
  }
}

export async function uploadScanResults(result: {
  directory: string;
  filesScanned: number;
  findings: unknown[];
  duration: number;
}): Promise<void> {
  const token = getStoredToken();
  if (!token) return;

  try {
    await apiRequest("/api/scans", {
      method: "POST",
      body: JSON.stringify(result),
    });
  } catch {
    // Silent fail
  }
}

export async function syncUser(): Promise<{ plan: string; email: string } | null> {
  try {
    const res = await apiRequest("/api/users/sync", { method: "POST" });
    if (!res.ok) return null;
    const data = await res.json();
    return data.user;
  } catch {
    return null;
  }
}

export async function getCheckoutUrl(): Promise<string | null> {
  try {
    const res = await apiRequest("/api/billing/checkout", { method: "POST" });
    if (!res.ok) return null;
    const data = await res.json();
    return data.url;
  } catch {
    return null;
  }
}
