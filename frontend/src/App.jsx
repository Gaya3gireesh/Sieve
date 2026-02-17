import { useEffect, useMemo, useState } from 'react'
import './App.css'

const API_BASE = (import.meta.env.VITE_API_BASE || '').replace(/\/$/, '')
console.log('API_BASE:', API_BASE)

// ── Cross-domain OAuth token helpers ────────────────────────────────────
function getSavedAuthToken() {
  return localStorage.getItem('sentinel_auth_token') || ''
}
function getSavedGithubLogin() {
  return localStorage.getItem('sentinel_github_login') || ''
}
function saveAuthCredentials(token, login) {
  localStorage.setItem('sentinel_auth_token', token)
  localStorage.setItem('sentinel_github_login', login)
}
function clearAuthCredentials() {
  localStorage.removeItem('sentinel_auth_token')
  localStorage.removeItem('sentinel_github_login')
}

/** Parse auth credentials from URL hash after OAuth redirect. */
function consumeHashCredentials() {
  const hash = window.location.hash
  if (!hash || !hash.includes('auth_token=')) return null
  const params = new URLSearchParams(hash.substring(1))
  const token = params.get('auth_token')
  const login = params.get('github_login')
  if (!token) return null
  // Clear the hash so the token doesn't linger in the URL / browser history.
  window.history.replaceState(null, '', window.location.pathname + window.location.search)
  return { token, login: login || 'unknown' }
}

const TAB_CONFIG = {
  queue: {
    label: 'Pending Queue',
    endpoint: '/api/prs/queue',
    empty: 'No PRs are currently in analysis queue.',
    icon: '⏳'
  },
  reviewed: {
    label: 'Reviewed & Approved',
    endpoint: '/api/prs/reviewed',
    empty: 'No approved PRs yet.',
    icon: '✅'
  },
  spam: {
    label: 'Spam / Closed',
    endpoint: '/api/prs/spam-closed',
    empty: 'No spam or auto-closed PRs yet.',
    icon: '🚫'
  },
}

async function fetchJson(path, params = {}, options = {}) {
  const query = new URLSearchParams()
  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null || value === '') return
    query.set(key, String(value))
  })

  const url = `${API_BASE}${path}${query.size ? `?${query.toString()}` : ''}`

  // Build headers, injecting Bearer token when stored locally (cross-domain).
  const headers = { ...(options.headers || {}) }
  const savedToken = getSavedAuthToken()
  if (savedToken && !headers['Authorization']) {
    headers['Authorization'] = `Bearer ${savedToken}`
  }

  const response = await fetch(url, {
    credentials: 'include',
    ...options,
    headers,
  })

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
  return date.toLocaleString(undefined, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
  })
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

function getVerdictBadgeClass(verdict) {
  const v = (verdict || '').toLowerCase()
  if (v.includes('approve') || v.includes('legit')) return 'badge-success'
  if (v.includes('spam')) return 'badge-error'
  if (v.includes('clarification')) return 'badge-warning'
  return 'badge-default'
}

function App() {
  const [activeTab, setActiveTab] = useState('queue')
  const [filterInput, setFilterInput] = useState('')
  const [repoFilter, setRepoFilter] = useState('')
  const [stats, setStats] = useState(null)
  const [itemsByTab, setItemsByTab] = useState({ queue: [], reviewed: [], spam: [] })

  // Refined loading states
  const [loading, setLoading] = useState({ stats: true, list: false, detail: false })
  // Track specific list loading to prevent stale data display
  const [listLoadingState, setListLoadingState] = useState(false)

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

  // Quick run state
  const [quickRepoInput, setQuickRepoInput] = useState('')
  const [syncOpenPrs, setSyncOpenPrs] = useState(true)
  const [quickBusy, setQuickBusy] = useState(false)
  const [quickMessage, setQuickMessage] = useState('')
  const [quickFailures, setQuickFailures] = useState([])

  // Load Setup Status
  async function loadSetupStatus() {
    try {
      const data = await fetchJson('/api/setup/status')
      setSetup({ loading: false, ...data })
    } catch (err) {
      setSetup((prev) => ({ ...prev, loading: false }))
      setError(`Setup status error: ${err.message}`)
    }
  }

  // Initial Auth Check
  useEffect(() => {
    const creds = consumeHashCredentials()
    if (creds) {
      saveAuthCredentials(creds.token, creds.login)
      setSetup((prev) => ({
        ...prev,
        connected: true,
        github_login: creds.login,
        loading: false,
      }))
    }
    loadSetupStatus()
  }, [])

  // Load Stats
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
        if (!cancelled) setLoading((prev) => ({ ...prev, stats: false }))
      }
    }
    loadStats()
    return () => { cancelled = true }
  }, [repoFilter, refreshTick])

  // Load List Data (Queue, Reviewed, Spam)
  useEffect(() => {
    let cancelled = false
    async function loadList() {
      // Clear selection when tab changes to avoid confusion
      setSelected(null)
      // Set precise loading state
      setListLoadingState(true)

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
        if (!cancelled) setListLoadingState(false)
      }
    }
    loadList()
    return () => { cancelled = true }
  }, [activeTab, repoFilter, refreshTick])

  const activeItems = useMemo(() => itemsByTab[activeTab] || [], [itemsByTab, activeTab])

  // Open Detail View
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

  // Filter Handling
  function applyFilter(event) {
    event.preventDefault()
    setRepoFilter(filterInput.trim())
    setSelected(null)
  }

  // Auth Actions
  function startGithubConnect() {
    const returnTo = `${window.location.origin}${window.location.pathname}${window.location.search}`
    window.location.href = `${API_BASE}/auth/github/start?next=${encodeURIComponent(returnTo)}`
  }

  async function disconnectGithub() {
    setQuickBusy(true)
    try {
      await fetchJson('/api/setup/logout', {}, { method: 'POST' })
      clearAuthCredentials()
      setQuickMessage('GitHub disconnected.')
      setQuickFailures([])
      await loadSetupStatus()
    } catch (err) {
      setError(`Disconnect error: ${err.message}`)
    } finally {
      setQuickBusy(false)
    }
  }

  // Setup / Run Actions
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
    { key: 'queue_pending', label: 'Pending Review', color: 'text-yellow-600' },
    { key: 'reviewed_approved', label: 'Approved', color: 'text-green-600' },
    { key: 'spam_closed', label: 'Spam Detected', color: 'text-red-600' },
    { key: 'active_repositories', label: 'Active Repos', color: 'text-blue-600' },
  ]

  // Render Helpers
  const renderSidebar = () => (
    <aside className="sidebar">
      <div className="sidebar-header">
        <span>Sentinel</span>
      </div>
      <nav className="sidebar-nav">
        {Object.entries(TAB_CONFIG).map(([key, tab]) => (
          <button
            key={key}
            className={`nav-item ${activeTab === key ? 'active' : ''}`}
            onClick={() => setActiveTab(key)}
          >
            <span>{tab.icon} {tab.label}</span>
          </button>
        ))}

        <div style={{ marginTop: 'auto', paddingTop: '1rem', borderTop: '1px solid #374151' }}>
          <div className="sidebar-sub-nav">
            <h4 style={{ fontSize: '0.8rem', color: '#6b7280', textTransform: 'uppercase', marginBottom: '0.5rem' }}>Configuration</h4>
            {/* Quick setup in sidebar for easy access, or keep in main? Let's keep a simplified status here */}
            <div style={{ fontSize: '0.85rem' }}>
              {setup.connected ? (
                <div style={{ color: '#10b981' }}>● Connected</div>
              ) : (
                <button onClick={startGithubConnect} className="btn btn-primary" style={{ width: '100%', fontSize: '0.8rem' }}>Connect GitHub</button>
              )}
            </div>
          </div>
        </div>
      </nav>
      <div className="sidebar-footer">
        © 2026 Sieve Security
      </div>
    </aside>
  )

  const renderSelectedDetail = () => {
    if (loading.detail) return <div className="loading-overlay"><div className="spinner"></div><p>Loading details...</p></div>
    if (!selected) return <div className="empty-state"><p>Select a Pull Request to view analysis</p></div>

    return (
      <div className="detail-content">
        <div className="detail-header">
          <h2>{selected.pr_title}</h2>
          <div className="detail-meta-row">
            <span className={`badge ${getVerdictBadgeClass(selected.verdict)}`}>
              {verdictLabel(selected.verdict)}
            </span>
            <span>#{selected.pr_number} in {selected.repo_full_name}</span>
            <span>by <strong>{selected.pr_author}</strong></span>
            <a href={selected.pr_url} target="_blank" rel="noreferrer" className="btn btn-ghost" style={{ padding: '0.2rem 0.5rem', fontSize: '0.8rem' }}>View on GitHub ↗</a>
          </div>
        </div>

        <div className="scores-grid">
          <div className="score-box">
            <span>Spam Probability</span>
            <strong style={{ color: selected.analysis?.spam_score > 0.5 ? '#dc2626' : '#16a34a' }}>
              {formatPercent(selected.analysis?.spam_score)}
            </strong>
          </div>
          <div className="score-box">
            <span>Effort Score</span>
            <strong>{formatPercent(selected.analysis?.effort_score)}</strong>
          </div>
        </div>

        <div className="analysis-section">
          <div className="analysis-item">
            <h4>Analysis Verdict</h4>
            <p>{selected.analysis?.verdict_reason || 'No detailed reason provided.'}</p>
          </div>

          <div className="analysis-item">
            <h4>Issue Alignment</h4>
            <p>
              <span className={`badge ${selected.analysis?.issue_aligned ? 'badge-success' : 'badge-warning'}`}>
                {selected.analysis?.issue_aligned ? 'Aligned' : 'Not Aligned'}
              </span>
              {' '} - {selected.analysis?.issue_alignment_reason}
            </p>
          </div>

          <div className="analysis-item">
            <h4>Description Quality</h4>
            <p>{selected.analysis?.description_match_reason}</p>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="app-shell">
      {renderSidebar()}

      <main className="main-content">
        {/* Header */}
        <header className="top-bar">
          <div className="page-title">
            <h1>Dashboard</h1>
            <p>Monitor and moderate Pull Requests</p>
          </div>

          <form onSubmit={applyFilter} className="filter-bar">
            <input
              type="text"
              className="search-input"
              placeholder="Filter by repo (owner/repo)..."
              value={filterInput}
              onChange={(e) => setFilterInput(e.target.value)}
            />
            {repoFilter && (
              <button type="button" className="btn btn-ghost" onClick={() => { setFilterInput(''); setRepoFilter(''); setSelected(null); }}>Clear</button>
            )}
            <button type="submit" className="btn btn-primary">Apply</button>
          </form>
        </header>

        {/* Global Error Banner */}
        {error && (
          <div style={{ background: '#fee2e2', color: '#991b1b', padding: '1rem', borderRadius: '0.5rem', marginBottom: '1.5rem', border: '1px solid #fecaca' }}>
            {error}
          </div>
        )}

        {/* Quick Actions (Collapsible or just standard panel) */}
        {!setup.connected || quickMessage || quickFailures.length > 0 || setup.oauth_enabled === false ? (
          <section className="quick-panel">
            <div className="quick-header">
              <h3>Quick Setup & Actions</h3>
              {setup.connected ?
                <span className="badge badge-success">Connected as {setup.github_login}</span> :
                <span className="badge badge-warning">Not Connected</span>}
            </div>

            <div className="quick-body">
              {!setup.connected && (
                <div style={{ marginBottom: '1rem' }}>
                  <p style={{ marginBottom: '0.5rem' }}>Connect your GitHub account to start managing repositories.</p>
                  <button onClick={startGithubConnect} disabled={!setup.oauth_enabled || quickBusy} className="btn btn-primary">Connect with GitHub</button>
                  {!setup.oauth_enabled && <p style={{ color: 'red', fontSize: '0.85rem', marginTop: '0.5rem' }}>OAuth not configured in backend.</p>}
                </div>
              )}

              {setup.connected && (
                <form onSubmit={authorizeAndRun} className="quick-form-grid">
                  <div className="form-group">
                    <label>Add / Scan Repositories (owner/repo per line)</label>
                    <textarea
                      className="form-input-area"
                      rows="2"
                      placeholder="owner/repo-name"
                      value={quickRepoInput}
                      onChange={(e) => setQuickRepoInput(e.target.value)}
                    />
                  </div>
                  <div style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
                    <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.9rem', cursor: 'pointer' }}>
                      <input type="checkbox" checked={syncOpenPrs} onChange={(e) => setSyncOpenPrs(e.target.checked)} />
                      Scan open PRs immediately
                    </label>
                    <button type="submit" className="btn btn-primary" disabled={quickBusy}>
                      {quickBusy ? 'Processing...' : 'Authorize & Run Scan'}
                    </button>
                    <button type="button" className="btn btn-ghost" onClick={disconnectGithub} disabled={quickBusy}>Disconnect</button>
                  </div>
                </form>
              )}

              {quickMessage && <div className="badge badge-info" style={{ marginTop: '1rem', display: 'block' }}>{quickMessage}</div>}
              {quickFailures.length > 0 && (
                <div style={{ marginTop: '1rem', color: '#991b1b', fontSize: '0.9rem' }}>
                  <strong>Failed to process:</strong>
                  <ul style={{ paddingLeft: '1.5rem', marginTop: '0.5rem' }}>
                    {quickFailures.map((f, i) => <li key={i}>{f}</li>)}
                  </ul>
                </div>
              )}
            </div>
          </section>
        ) : null}

        {/* Stats Grid */}
        <section className="stats-grid">
          {statCards.map((card) => (
            <div key={card.key} className="stat-card">
              <span className="stat-label">{card.label}</span>
              <span className="stat-value">
                {loading.stats ? '-' : (stats?.[card.key] ?? 0)}
              </span>
            </div>
          ))}
        </section>

        {/* Main Content Split */}
        <section className="content-split">
          <div className="list-card">
            <div className="list-header">
              <h3>{TAB_CONFIG[activeTab].label}</h3>
              {listLoadingState && <span className="badge badge-default">Refreshing...</span>}
            </div>

            <div className="list-scroll-area">
              {listLoadingState ? (
                <div className="loading-overlay">
                  <div className="spinner"></div>
                  <p>Loading...</p>
                </div>
              ) : activeItems.length === 0 ? (
                <div className="empty-state">
                  <span style={{ fontSize: '2rem', marginBottom: '1rem' }}>{TAB_CONFIG[activeTab].icon}</span>
                  <p>{TAB_CONFIG[activeTab].empty}</p>
                </div>
              ) : (
                <div>
                  {activeItems.map((item) => (
                    <div
                      key={item.id}
                      className={`list-item ${selected && selected.id === item.id ? 'selected' : ''}`}
                      onClick={() => openDetail(item.id)}
                    >
                      <div className="item-main">
                        <strong>{item.repo_full_name} #{item.pr_number}</strong>
                        <p>{item.pr_title}</p>
                        <span className={`badge ${getVerdictBadgeClass(item.verdict)}`} style={{ marginTop: '0.5rem' }}>
                          {verdictLabel(item.verdict)}
                        </span>
                      </div>
                      <div className="item-meta">
                        <small className="item-date">{prettyDate(item.updated_at || item.created_at)}</small>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          <aside className="detail-card">
            {renderSelectedDetail()}
          </aside>
        </section>
      </main>
    </div>
  )
}

export default App
