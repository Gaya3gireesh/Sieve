import type { ScanBucket } from "../types";

type Props = {
  activeTab: ScanBucket;
  onChange: (tab: ScanBucket) => void;
};

const TABS: Array<{ id: ScanBucket; label: string }> = [
  { id: "queue", label: "Queue" },
  { id: "reviewed", label: "Reviewed" },
  { id: "spam_closed", label: "Spam / Closed" },
];

export function PrTabs({ activeTab, onChange }: Props) {
  return (
    <nav className="tabs" aria-label="PR status tabs">
      {TABS.map((tab) => (
        <button
          key={tab.id}
          type="button"
          className={tab.id === activeTab ? "tab active" : "tab"}
          onClick={() => onChange(tab.id)}
        >
          {tab.label}
        </button>
      ))}
    </nav>
  );
}
