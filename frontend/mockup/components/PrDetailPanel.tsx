import type { ScanItem } from "../types";

type Props = {
  scan: ScanItem | null;
};

function yesNo(value: boolean | null): string {
  if (value === null) return "N/A";
  return value ? "Yes" : "No";
}

export function PrDetailPanel({ scan }: Props) {
  if (!scan) {
    return (
      <aside className="detail-panel">
        <h3>PR Detail</h3>
        <p className="muted">Select a PR row to inspect the analysis breakdown.</p>
      </aside>
    );
  }

  const analysis = scan.analysis;

  return (
    <aside className="detail-panel">
      <h3>PR Detail</h3>
      <p>
        <strong>{scan.repo_full_name}</strong> #{scan.pr_number}
      </p>
      <p className="muted">{scan.pr_title}</p>

      <dl className="detail-grid">
        <dt>Sentinel Verdict</dt>
        <dd>{scan.verdict}</dd>

        <dt>Effort Score</dt>
        <dd>{analysis.effort_score ?? "N/A"}</dd>

        <dt>Signal-to-Noise</dt>
        <dd>{analysis.signal_to_noise_ratio ?? "N/A"}</dd>

        <dt>Issue Aligned</dt>
        <dd>{yesNo(analysis.issue_aligned)}</dd>

        <dt>Description Match</dt>
        <dd>{yesNo(analysis.description_match)}</dd>

        <dt>Spam Score</dt>
        <dd>{analysis.spam_score ?? "N/A"}</dd>

        <dt>Quality Score</dt>
        <dd>{analysis.quality_score ?? "N/A"}</dd>
      </dl>

      <h4>Verdict Reason</h4>
      <p className="muted">{analysis.verdict_reason || "No reason recorded."}</p>
    </aside>
  );
}
