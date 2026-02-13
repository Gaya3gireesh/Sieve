import type { DashboardStatsResponse } from "../types";

type Props = {
  stats: DashboardStatsResponse["stats"];
};

export function StatsCards({ stats }: Props) {
  const cards = [
    { label: "Pending Queue", value: stats.queue_pending },
    { label: "Reviewed", value: stats.reviewed_approved },
    { label: "Spam / Closed", value: stats.spam_closed },
    { label: "Total Scans", value: stats.total_scans },
    { label: "Protected Repos", value: stats.total_repositories },
    { label: "Active Repos", value: stats.active_repositories },
  ];

  return (
    <section className="stats-grid">
      {cards.map((card) => (
        <article key={card.label} className="stat-card">
          <div className="stat-label">{card.label}</div>
          <div className="stat-value">{card.value}</div>
        </article>
      ))}
    </section>
  );
}
