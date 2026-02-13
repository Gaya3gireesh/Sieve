import type { ScanItem } from "../types";

type Props = {
  rows: ScanItem[];
  onOpenDetail: (row: ScanItem) => void;
};

export function PrTable({ rows, onOpenDetail }: Props) {
  if (!rows.length) {
    return <p className="empty">No PRs found for this tab.</p>;
  }

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Repository</th>
            <th>PR</th>
            <th>Author</th>
            <th>Verdict</th>
            <th>Created</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id}>
              <td>{row.repo_full_name}</td>
              <td>
                <a href={row.pr_url} target="_blank" rel="noreferrer">
                  #{row.pr_number} {row.pr_title}
                </a>
              </td>
              <td>{row.pr_author}</td>
              <td>{row.verdict}</td>
              <td>{row.created_at ? new Date(row.created_at).toLocaleString() : "-"}</td>
              <td>
                <button type="button" onClick={() => onOpenDetail(row)}>
                  View
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
