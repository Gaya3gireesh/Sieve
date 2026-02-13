"use client";

import { useEffect, useMemo, useState } from "react";

import { PrDetailPanel } from "../../components/PrDetailPanel";
import { PrTable } from "../../components/PrTable";
import { PrTabs } from "../../components/PrTabs";
import { StatsCards } from "../../components/StatsCards";
import {
  fetchDashboardStats,
  fetchQueue,
  fetchReviewed,
  fetchScanDetail,
  fetchSpamClosed,
} from "../../lib/api";
import type { DashboardStatsResponse, ScanBucket, ScanItem } from "../../types";

export default function DashboardPage() {
  const [activeTab, setActiveTab] = useState<ScanBucket>("queue");
  const [stats, setStats] = useState<DashboardStatsResponse | null>(null);
  const [queueRows, setQueueRows] = useState<ScanItem[]>([]);
  const [reviewedRows, setReviewedRows] = useState<ScanItem[]>([]);
  const [spamRows, setSpamRows] = useState<ScanItem[]>([]);
  const [selectedScan, setSelectedScan] = useState<ScanItem | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let ignore = false;

    async function loadAll() {
      setLoading(true);
      setError(null);
      try {
        const [statsResp, queueResp, reviewedResp, spamResp] = await Promise.all([
          fetchDashboardStats(),
          fetchQueue(),
          fetchReviewed(),
          fetchSpamClosed(),
        ]);
        if (ignore) return;
        setStats(statsResp);
        setQueueRows(queueResp.items);
        setReviewedRows(reviewedResp.items);
        setSpamRows(spamResp.items);
      } catch (err) {
        if (ignore) return;
        setError(err instanceof Error ? err.message : "Failed to load dashboard.");
      } finally {
        if (!ignore) setLoading(false);
      }
    }

    void loadAll();
    return () => {
      ignore = true;
    };
  }, []);

  const activeRows = useMemo(() => {
    if (activeTab === "queue") return queueRows;
    if (activeTab === "reviewed") return reviewedRows;
    return spamRows;
  }, [activeTab, queueRows, reviewedRows, spamRows]);

  async function onOpenDetail(row: ScanItem) {
    try {
      const detail = await fetchScanDetail(row.id);
      setSelectedScan(detail);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load PR detail.");
    }
  }

  return (
    <main className="dashboard-wrap">
      <header>
        <h1>Sentinel Owner Dashboard</h1>
        <p>
          Track pending scans, approved contributions, and spam/closed pull requests.
        </p>
      </header>

      {error ? <p className="error">{error}</p> : null}
      {loading ? <p className="muted">Loading dashboard...</p> : null}

      {stats ? <StatsCards stats={stats.stats} /> : null}

      <section className="content-grid">
        <div>
          <PrTabs activeTab={activeTab} onChange={setActiveTab} />
          <PrTable rows={activeRows} onOpenDetail={onOpenDetail} />
        </div>
        <PrDetailPanel scan={selectedScan} />
      </section>

      <style jsx>{`
        .dashboard-wrap {
          padding: 24px;
          max-width: 1200px;
          margin: 0 auto;
          color: #13222c;
          font-family: "Avenir Next", "Trebuchet MS", sans-serif;
        }
        h1 {
          margin: 0 0 6px;
          font-size: 2rem;
        }
        p {
          margin: 0 0 16px;
          color: #375063;
        }
        .content-grid {
          display: grid;
          grid-template-columns: 2fr 1fr;
          gap: 16px;
          margin-top: 18px;
        }
        .error {
          color: #9f1239;
          background: #ffe4e6;
          padding: 10px;
          border-radius: 8px;
        }
        .muted {
          color: #4f6b7a;
        }
        :global(.stats-grid) {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
          gap: 12px;
          margin: 16px 0;
        }
        :global(.stat-card) {
          background: #f8f8ef;
          border: 1px solid #dae3d5;
          border-radius: 12px;
          padding: 12px;
        }
        :global(.stat-label) {
          color: #4f6b7a;
          font-size: 0.9rem;
        }
        :global(.stat-value) {
          font-size: 1.4rem;
          font-weight: 700;
          margin-top: 6px;
        }
        :global(.tabs) {
          display: flex;
          gap: 8px;
          margin-bottom: 10px;
        }
        :global(.tab) {
          border: 1px solid #c7d3dc;
          background: #edf3f7;
          color: #1f3443;
          border-radius: 8px;
          padding: 8px 12px;
          cursor: pointer;
        }
        :global(.tab.active) {
          background: #0f766e;
          border-color: #0f766e;
          color: #fff;
        }
        :global(.table-wrap) {
          overflow-x: auto;
          border: 1px solid #d8e0df;
          border-radius: 12px;
          background: #fff;
        }
        :global(table) {
          width: 100%;
          border-collapse: collapse;
          min-width: 640px;
        }
        :global(th),
        :global(td) {
          text-align: left;
          padding: 10px;
          border-bottom: 1px solid #edf1ee;
          vertical-align: top;
        }
        :global(th) {
          background: #f7faf9;
          font-size: 0.9rem;
          color: #3b5566;
        }
        :global(.empty) {
          padding: 12px;
          border: 1px dashed #c8d7da;
          border-radius: 8px;
          color: #4f6b7a;
        }
        :global(.detail-panel) {
          border: 1px solid #d8e0df;
          border-radius: 12px;
          padding: 14px;
          background: #fcfdfd;
          max-height: fit-content;
        }
        :global(.detail-grid) {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 6px 10px;
        }
        :global(.detail-grid dt) {
          font-weight: 600;
          color: #385365;
        }
        :global(.detail-grid dd) {
          margin: 0;
        }
        @media (max-width: 900px) {
          .content-grid {
            grid-template-columns: 1fr;
          }
        }
      `}</style>
    </main>
  );
}
