import type {
  DashboardStatsResponse,
  ScanItem,
  ScanListResponse,
} from "../types";

const API_BASE = process.env.NEXT_PUBLIC_SENTINEL_API_BASE ?? "http://127.0.0.1:8000";

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, { cache: "no-store" });
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`API ${path} failed (${response.status}): ${body}`);
  }
  return (await response.json()) as T;
}

export async function fetchDashboardStats(): Promise<DashboardStatsResponse> {
  return getJson<DashboardStatsResponse>("/api/dashboard/stats");
}

export async function fetchQueue(): Promise<ScanListResponse> {
  return getJson<ScanListResponse>("/api/prs/queue?limit=100");
}

export async function fetchReviewed(): Promise<ScanListResponse> {
  return getJson<ScanListResponse>("/api/prs/reviewed?limit=100");
}

export async function fetchSpamClosed(): Promise<ScanListResponse> {
  return getJson<ScanListResponse>("/api/prs/spam-closed?limit=100&include_soft_fail=true");
}

export async function fetchScanDetail(scanId: string): Promise<ScanItem> {
  return getJson<ScanItem>(`/api/prs/${scanId}`);
}
