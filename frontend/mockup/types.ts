export type ScanBucket = "queue" | "reviewed" | "spam_closed";

export type ScanAnalysis = {
  author_account_age_days: number | null;
  spam_score: number | null;
  is_spam: boolean | null;
  spam_reason: string | null;
  effort_score: number | null;
  signal_to_noise_ratio: number | null;
  issue_number: number | null;
  issue_aligned: boolean | null;
  issue_alignment_score: number | null;
  issue_alignment_reason: string | null;
  description_match: boolean | null;
  description_match_score: number | null;
  description_match_reason: string | null;
  quality_score: number | null;
  quality_issues: Array<Record<string, unknown>>;
  policy_violations: Array<Record<string, unknown>>;
  verdict_reason: string | null;
};

export type ScanItem = {
  id: string;
  repo_full_name: string;
  pr_number: number;
  pr_title: string;
  pr_author: string;
  pr_url: string;
  verdict: string;
  bucket: ScanBucket;
  auto_closed: boolean;
  created_at: string | null;
  updated_at: string | null;
  analysis: ScanAnalysis;
};

export type ScanListResponse = {
  items: ScanItem[];
  count: number;
};

export type DashboardStatsResponse = {
  repo_filter: string | null;
  stats: {
    queue_pending: number;
    reviewed_approved: number;
    spam_closed: number;
    auto_closed: number;
    needs_clarification: number;
    total_scans: number;
    total_repositories: number;
    active_repositories: number;
  };
  verdict_breakdown: Record<string, number>;
};
