import { useEffect, useMemo, useState } from 'react'
import './App.css'

const API_BASE = (import.meta.env.VITE_API_BASE || '').replace(/\/$/, '')
console.log('API_BASE:', API_BASE, 'VITE_API_BASE env:', import.meta.env.VITE_API_BASE)

const TAB_CONFIG = {
  queue: {
    label: 'Queue',
    endpoint: '/api/prs/queue',
    empty: 'No PRs are currently in analysis queue.',
  },
  reviewed: {
    label: 'Reviewed',
    endpoint: '/api/prs/reviewed',
    empty: 'No approved PRs yet.',
  },
  spam: {
    label: 'Spam / Closed',
    endpoint: '/api/prs/spam-closed',
    empty: 'No spam or auto-closed PRs yet.',
  },
}

async function fetchJson(path, params = {}, options = {}) {
  const query = new URLSearchParams()
  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null || value === '') return
    query.set(key, String(value))
  })

  const url = `${API_BASE}${path}${query.size ? `?${query.toString()}` : ''}`
  const response = await fetch(url, {
    credentials: 'include',
    ...options,
  })

  // Read body once and only once
  let bodyText = ''
  try {
    bodyText = await response.text()
  } catch (e) {
    console.error('Error reading response body:', e)
    throw new Error(`Request failed (${response.status}): could not read response`)
  }

  if (!response.ok) {
    let message = `Request failed (${response.status})`
    if (bodyText) {
      try {
        const body = JSON.parse(bodyText)
        message = body.detail || body.message || message
      } catch {
        message = bodyText
      }
    }
    throw new Error(message)
  }

  // Parse JSON from the body we already read
  const contentType = response.headers.get('content-type') || ''
  if (!contentType.includes('application/json')) return {}
  
  if (!bodyText) return {}
  
  try {
    return JSON.parse(bodyText)
  } catch (e) {
    console.error('Error parsing JSON response:', e)
    return {}
  }
}

function prettyDate(isoString) {
  if (!isoString) return 'Unknown'
  const date = new Date(isoString)
  if (Number.isNaN(date.getTime())) return 'Unknown'
  return date.toLocaleString()
}

function formatPercent(value) {
  if (value === undefined || value === null || Number.isNaN(Number(value))) return 'N/A'
  const n = Number(value)
  const pct = n <= 1 ? n * 100 : n
  return `${pct.toFixed(1)}%`
}

function verdictLabel(verdict) {
  return String(verdict || 'unknown').replaceAll('_', ' ')
}

function App() {
  const [activeTab, setActiveTab] = useState('queue')
  const [filterInput, setFilterInput] = useState('')
  const [repoFilter, setRepoFilter] = useState('')
  const [stats, setStats] = useState(null)
  const [itemsByTab, setItemsByTab] = useState({ queue: [], reviewed: [], spam: [] })
  const [loading, setLoading] = useState({ stats: true, list: false, detail: false })
  const [selected, setSelected] = useState(null)
  const [error, setError] = useState('')

  const [refreshTick, setRefreshTick] = useState(0)
  const [setup, setSetup] = useState({
    loading: true,
    oauth_enabled: false,
    connected: false,
    github_login: null,
    webhook_target: '',
    webhook_target_public: false,
  })
  const [quickRepoInput, setQuickRepoInput] = useState('')
  const [syncOpenPrs, setSyncOpenPrs] = useState(true)
  const [quickBusy, setQuickBusy] = useState(false)
  const [quickMessage, setQuickMessage] = useState('')
  const [quickFailures, setQuickFailures] = useState([])

  async function loadSetupStatus() {
    try {
      const data = await fetchJson('/api/setup/status')
      setSetup({ loading: false, ...data })
    } catch (err) {
      setSetup((prev) => ({ ...prev, loading: false }))
      setError(`Setup status error: ${err.message}`)
    }
  }

  useEffect(() => {
    loadSetupStatus()
  }, [])

  useEffect(() => {
    let cancelled = false

    async function loadStats() {
      setLoading((prev) => ({ ...prev, stats: true }))
      try {
        const data = await fetchJson('/api/dashboard/stats', { repo_full_name: repoFilter })
        if (cancelled) return
        setStats(data.stats)
        setError('')
      } catch (err) {
        if (cancelled) return
        setError(`Stats error: ${err.message}`)
      } finally {
        if (!cancelled) {
          setLoading((prev) => ({ ...prev, stats: false }))
        }
      }
    }

    loadStats()
    return () => {
      cancelled = true
    }
  }, [repoFilter, refreshTick])

  useEffect(() => {
    let cancelled = false

    async function loadList() {
      setLoading((prev) => ({ ...prev, list: true }))
      try {
        const config = TAB_CONFIG[activeTab]
        const data = await fetchJson(config.endpoint, { limit: 100, repo_full_name: repoFilter })
        if (cancelled) return
        setItemsByTab((prev) => ({ ...prev, [activeTab]: data.items || [] }))
        setError('')
      } catch (err) {
        if (cancelled) return
        setError(`List error: ${err.message}`)
      } finally {
        if (!cancelled) {
          setLoading((prev) => ({ ...prev, list: false }))
        }
      }
    }

    loadList()
    return () => {
      cancelled = true
    }
  }, [activeTab, repoFilter, refreshTick])

  const activeItems = useMemo(() => itemsByTab[activeTab] || [], [itemsByTab, activeTab])

  async function openDetail(scanId) {
    setLoading((prev) => ({ ...prev, detail: true }))
    try {
      const data = await fetchJson(`/api/prs/${scanId}`)
      setSelected(data)
      setError('')
    } catch (err) {
      setError(`Detail error: ${err.message}`)
    } finally {
      setLoading((prev) => ({ ...prev, detail: false }))
    }
  }

  function applyFilter(event) {
    event.preventDefault()
    setRepoFilter(filterInput.trim())
    setSelected(null)
  }

  function startGithubConnect() {
    const returnTo = `${window.location.pathname}${window.location.search}`
    window.location.href = `/auth/github/start?next=${encodeURIComponent(returnTo)}`
  }

  async function disconnectGithub() {
    setQuickBusy(true)
    try {
      await fetchJson('/api/setup/logout', {}, { method: 'POST' })
      setQuickMessage('GitHub disconnected.')
      setQuickFailures([])
      await loadSetupStatus()
    } catch (err) {
      setError(`Disconnect error: ${err.message}`)
    } finally {
      setQuickBusy(false)
    }
  }

  async function authorizeAndRun(event) {
    event.preventDefault()
    setQuickMessage('')
    setQuickFailures([])

    if (!quickRepoInput.trim()) {
      setError('Enter at least one repository in owner/repo format.')
      return
    }

    setQuickBusy(true)
    try {
      const data = await fetchJson('/api/setup/authorize-repos', {}, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repo_full_names: quickRepoInput,
          sync_open_prs: syncOpenPrs,
        }),
      })
      setQuickMessage(data.message || 'Authorization completed.')
      setQuickFailures(Array.isArray(data.failures) ? data.failures : [])
      setError('')
      setRefreshTick((v) => v + 1)
      await loadSetupStatus()
    } catch (err) {
      setError(`Authorize/run error: ${err.message}`)
    } finally {
      setQuickBusy(false)
    }
  }

  const statCards = [
    { key: 'queue_pending', label: 'Pending Queue' },
    { key: 'reviewed_approved', label: 'Reviewed / Approved' },
    { key: 'spam_closed', label: 'Spam / Closed' },
    { key: 'auto_closed', label: 'Auto Closed' },
    { key: 'needs_clarification', label: 'Needs Clarification' },
    { key: 'active_repositories', label: 'Active Repositories' },
  ]

  return (
    <div className="app-shell">
      <header className="page-header">
        <div>
          <p className="eyebrow">Sentinel</p>
          <h1>PR Moderation Dashboard</h1>
          <p className="subtitle">Monitor queued scans, approved PRs, and spam closures across connected repositories.</p>
        </div>
        <form onSubmit={applyFilter} className="filter-form">
          <label htmlFor="repo-filter">Repository Filter</label>
          <input
            id="repo-filter"
            type="text"
            placeholder="owner/repo"
            value={filterInput}
            onChange={(event) => setFilterInput(event.target.value)}
          />
          <div className="filter-actions">
            <button type="submit">Apply</button>
            <button
              type="button"
              className="ghost"
              onClick={() => {
                setFilterInput('')
                setRepoFilter('')
                setSelected(null)
              }}
            >
              Clear
            </button>
          </div>
        </form>
      </header>

      <section className="quick-panel">
        <div className="quick-head">
          <h2>Quick Connect and Run</h2>
          {setup.loading ? (
            <span className="muted-pill">Checking GitHub session...</span>
          ) : setup.connected ? (
            <span className="muted-pill success">Connected as {setup.github_login}</span>
          ) : (
            <span className="muted-pill warn">Not connected</span>
          )}
        </div>

        {!setup.oauth_enabled ? (
          <div className="banner error">Set <code>GITHUB_OAUTH_CLIENT_ID</code> and <code>GITHUB_OAUTH_CLIENT_SECRET</code> in backend <code>.env</code>.</div>
        ) : null}

        {!setup.webhook_target_public ? (
          <div className="banner error">Webhook URL is not public HTTPS. You can still run one-time scans now; set backend <code>PUBLIC_BASE_URL</code> later for live GitHub webhooks.</div>
        ) : null}

        <div className="quick-actions">
          {!setup.connected ? (
            <button type="button" onClick={startGithubConnect} disabled={!setup.oauth_enabled || quickBusy}>
              Connect GitHub
            </button>
          ) : (
            <button type="button" className="ghost" onClick={disconnectGithub} disabled={quickBusy}>
              Disconnect GitHub
            </button>
          )}
          <span className="webhook-path">Webhook target: {setup.webhook_target || 'N/A'}</span>
        </div>

        <form onSubmit={authorizeAndRun} className="quick-form">
          <label htmlFor="quick-repos">Repository Names (owner/repo)</label>
          <textarea
            id="quick-repos"
            rows="3"
            placeholder={'owner/repo-a\nowner/repo-b'}
            value={quickRepoInput}
            onChange={(event) => setQuickRepoInput(event.target.value)}
          />
          <label className="inline-check">
            <input
              type="checkbox"
              checked={syncOpenPrs}
              onChange={(event) => setSyncOpenPrs(event.target.checked)}
            />
            Queue existing open PRs immediately
          </label>
          <button
            type="submit"
            disabled={quickBusy || !setup.connected}
          >
            {quickBusy ? 'Running...' : 'Authorize Repositories and Run'}
          </button>
        </form>

        {quickMessage ? <div className="banner ok">{quickMessage}</div> : null}
        {quickFailures.length > 0 ? (
          <div className="failure-list">
            <strong>Failures</strong>
            <ul>
              {quickFailures.slice(0, 5).map((row) => (
                <li key={row}>{row}</li>
              ))}
            </ul>
          </div>
        ) : null}
      </section>

      {error ? <div className="banner error">{error}</div> : null}

      <section className="stats-grid">
        {statCards.map((card) => (
          <article key={card.key} className="stat-card">
            <p>{card.label}</p>
            <strong>{loading.stats ? '...' : stats?.[card.key] ?? 0}</strong>
          </article>
        ))}
      </section>

      <section className="panel">
        <div className="tabs" role="tablist" aria-label="PR lists">
          {Object.entries(TAB_CONFIG).map(([key, tab]) => (
            <button
              key={key}
              role="tab"
              aria-selected={activeTab === key}
              className={activeTab === key ? 'active' : ''}
              onClick={() => {
                setActiveTab(key)
                setSelected(null)
              }}
            >
              {tab.label}
            </button>
          ))}
        </div>

        <div className="content-grid">
          <div className="list-panel">
            <div className="list-head">
              <h2>{TAB_CONFIG[activeTab].label}</h2>
              <span>{loading.list ? 'Loading...' : `${activeItems.length} results`}</span>
            </div>

            {activeItems.length === 0 && !loading.list ? (
              <div className="empty">{TAB_CONFIG[activeTab].empty}</div>
            ) : (
              <div className="list-table">
                {activeItems.map((item) => (
                  <button
                    key={item.id}
                    className="row"
                    onClick={() => openDetail(item.id)}
                  >
                    <div>
                      <strong>{item.repo_full_name} #{item.pr_number}</strong>
                      <p>{item.pr_title}</p>
                    </div>
                    <div className="row-meta">
                      <span className="pill">{verdictLabel(item.verdict)}</span>
                      <small>{prettyDate(item.updated_at || item.created_at)}</small>
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>

          <aside className="detail-panel">
            {loading.detail ? (
              <p>Loading PR detail...</p>
            ) : !selected ? (
              <p>Select a PR to view the Sentinel verdict breakdown.</p>
            ) : (
              <>
                <h3>{selected.repo_full_name} #{selected.pr_number}</h3>
                <p className="detail-title">{selected.pr_title}</p>
                <p>
                  Author: <strong>{selected.pr_author}</strong>
                </p>
                <p>
                  Verdict: <strong>{verdictLabel(selected.verdict)}</strong>
                </p>
                <p>
                  PR Link: <a href={selected.pr_url} target="_blank" rel="noreferrer">Open on GitHub</a>
                </p>

                <div className="analysis-grid">
                  <article>
                    <span>Effort Score</span>
                    <strong>{formatPercent(selected.analysis?.effort_score)}</strong>
                  </article>
                  <article>
                    <span>Issue Aligned</span>
                    <strong>{selected.analysis?.issue_aligned === null || selected.analysis?.issue_aligned === undefined ? 'N/A' : selected.analysis.issue_aligned ? 'Yes' : 'No'}</strong>
                  </article>
                  <article>
                    <span>Description Match</span>
                    <strong>{selected.analysis?.description_match === null || selected.analysis?.description_match === undefined ? 'N/A' : selected.analysis.description_match ? 'Yes' : 'No'}</strong>
                  </article>
                  <article>
                    <span>Spam Score</span>
                    <strong>{formatPercent(selected.analysis?.spam_score)}</strong>
                  </article>
                </div>

                <div className="analysis-notes">
                  <p><strong>Verdict Reason:</strong> {selected.analysis?.verdict_reason || 'None'}</p>
                  <p><strong>Spam Reason:</strong> {selected.analysis?.spam_reason || 'None'}</p>
                  <p><strong>Issue Alignment Reason:</strong> {selected.analysis?.issue_alignment_reason || 'None'}</p>
                  <p><strong>Description Match Reason:</strong> {selected.analysis?.description_match_reason || 'None'}</p>
                </div>
              </>
            )}
          </aside>
        </div>
      </section>
    </div>
  )
}

export default App
