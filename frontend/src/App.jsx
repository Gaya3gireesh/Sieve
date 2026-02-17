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
    visible_repositories: [],
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
        visible_repositories: prev.visible_repositories || []
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
  const renderRepoGrid = () => {
    if (setup.loading) {
      return <div style={{ color: 'var(--text-muted)' }}>Loading repositories...</div>
    }
    if (Array.isArray(setup.visible_repositories) && setup.visible_repositories.length > 0) {
      return setup.visible_repositories.map((r) => (
        <button key={r.full_name} className="repo-card" onClick={() => { setRepoFilter(r.full_name); setFilterInput(r.full_name); setActiveTab('queue'); setSelected(null); }}>
          <div className="repo-card-title">{r.full_name}</div>
          <div className="repo-card-sub">{r.description || r.full_name}</div>
        </button>
      ))
    }
    return <div style={{ color: 'var(--text-muted)' }}>No repositories available. Try refreshing or connecting a different account.</div>
  }

  const renderSidebar = () => (
    <aside className="sidebar">
      <div className="sidebar-header">
        <span className="brand-logo">🛡️</span>
        <span className="brand-name">Sentinel</span>
      </div>

      <div className="user-profile-section">
        {setup.connected ? (
          <div className="user-card">
            <div className="user-avatar-placeholder">{setup.github_login.charAt(0).toUpperCase()}</div>
            <div className="user-info">
              <span className="user-name">{setup.github_login}</span>
              <span className="user-status">● Connected</span>
            </div>
          </div>
        ) : (
          <div className="user-card disconnected">
            <div className="user-info">
              <span className="user-status">○ Guest</span>
            </div>
          </div>
        )}
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

        <div style={{ marginTop: '2rem', padding: '0 1rem', borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: '1rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
            <h4 style={{ fontSize: '0.75rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600, margin: 0 }}>Repositories</h4>
            <button onClick={loadSetupStatus} className="btn-icon" title="Refresh List" style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#64748b', fontSize: '0.8rem', padding: 0 }}>↻</button>
          </div>

          <div className="repo-list-container">
            {setup.loading && <div style={{ color: '#94a3b8', fontSize: '0.85rem', fontStyle: 'italic' }}>Loading...</div>}

            {!setup.loading && Array.isArray(setup.visible_repositories) && setup.visible_repositories.length > 0 && (
              <div className="repo-list">
                {setup.visible_repositories.slice(0, 15).map((r) => (
                  <button
                    key={r.full_name}
                    className="repo-item"
                    onClick={() => { setRepoFilter(r.full_name); setFilterInput(r.full_name); setActiveTab('queue'); setSelected(null); }}
                    title={r.full_name}
                  >
                    <span className="repo-name">{r.full_name.split('/')[1]}</span>
                  </button>
                ))}
                {setup.visible_repositories.length > 15 && <div style={{ fontSize: '0.75rem', color: '#64748b', padding: '0.5rem' }}>+ {setup.visible_repositories.length - 15} more</div>}
              </div>
            )}

            {!setup.loading && (!setup.visible_repositories || setup.visible_repositories.length === 0) && (
              <div style={{ color: '#64748b', fontSize: '0.85rem' }}>
                No active repositories found.
                {!setup.connected && (
                  <button onClick={startGithubConnect} className="link-button" style={{ display: 'block', marginTop: '0.5rem', color: '#6366f1', background: 'none', border: 'none', padding: 0, textDecoration: 'underline', cursor: 'pointer' }}>
                    Connect to GitHub
                  </button>
                )}
              </div>
            )}
          </div>
        </div>
      </nav>
      <div className="sidebar-footer">
        {setup.connected ? (
          <button onClick={disconnectGithub} className="btn btn-outline-danger full-width" disabled={quickBusy}>
            Disconnect GitHub
          </button>
        ) : (
          <button onClick={startGithubConnect} className="btn btn-primary full-width">
            Connect GitHub
          </button>
        )}
        <div className="footer-copy">© 2026 Sieve Security</div>
      </div>
    </aside>
  )

  const renderSelectedDetail = () => {
    if (loading.detail) return <div className="loading-overlay"><div className="spinner"></div><p>Loading details...</p></div>
    if (!selected) return <div className="detail-placeholder">Select an item to view details</div>
    const isPr = !!selected.pr_number
    return (
      <article className="detail-card">
        <header className="detail-header">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
            <h2>{isPr ? selected.pr_title : selected.repo_full_name}</h2>
            <a href={selected.pr_url || `https://github.com/${selected.repo_full_name}`} target="_blank" rel="noreferrer" className="btn btn-secondary btn-sm" style={{ fontSize: '0.8rem' }}>
              View on GitHub ↗
            </a>
          </div>

          <div className="detail-meta-row">
            <span className={`badge ${getVerdictBadgeClass(selected.verdict)}`}>
              {selected.verdict}
            </span>
            {isPr && <span className="badge badge-default">PR #{selected.pr_number}</span>}
            <span className="badge badge-default">{prettyDate(selected.created_at)}</span>
            <span className="badge badge-default">{selected.pr_author}</span>
          </div>
        </header>

        {selected.analysis && (
          <div className="analysis-content" style={{ marginTop: '2rem' }}>
            <div className="scores-grid">
              <div className="score-box">
                <div style={{ color: '#64748b', fontSize: '0.85rem', marginBottom: '0.5rem' }}>SPAM SCORE</div>
                <strong style={{ color: selected.analysis.spam_score > 50 ? '#ef4444' : '#10b981' }}>
                  {selected.analysis.spam_score}
                </strong>
              </div>
              <div className="score-box">
                <div style={{ color: '#64748b', fontSize: '0.85rem', marginBottom: '0.5rem' }}>QUALITY SCORE</div>
                <strong>{selected.analysis.quality_score}</strong>
              </div>
            </div>

            <div className="analysis-item">
              <h4>Verdict Reason</h4>
              <p>{selected.analysis.verdict_reason}</p>
            </div>

            <div className="analysis-item">
              <h4>Quality Issues</h4>
              {selected.analysis.quality_issues && selected.analysis.quality_issues.length > 0 ? (
                <ul style={{ paddingLeft: '1.2rem', color: '#64748b' }}>
                  {selected.analysis.quality_issues.map((issue, idx) => (
                    <li key={idx}>{issue}</li>
                  ))}
                </ul>
              ) : <span style={{ color: '#94a3b8', fontStyle: 'italic' }}>None</span>}
            </div>

            <div className="analysis-item">
              <h4>Policy Violations</h4>
              {selected.analysis.policy_violations && selected.analysis.policy_violations.length > 0 ? (
                <ul style={{ paddingLeft: '1.2rem', color: '#ef4444' }}>
                  {selected.analysis.policy_violations.map((violation, idx) => (
                    <li key={idx}>{violation}</li>
                  ))}
                </ul>
              ) : <span style={{ color: '#94a3b8', fontStyle: 'italic' }}>None</span>}
            </div>
          </div>
        )}
        {/* System Actions, Comments and Inferences */}
        <div style={{ marginTop: '1.5rem' }}>
          <h4 style={{ marginBottom: '0.75rem', color: '#334155' }}>System Activity & Comments</h4>

          {selected.system_actions && selected.system_actions.length > 0 ? (
            <div className="timeline">
              {selected.system_actions.map((act, i) => (
                <div key={i} className="action-item">
                  <div className="action-meta">
                    <strong className="action-type">{act.type}</strong>
                    <span className="action-time">{prettyDate(act.timestamp)}</span>
                  </div>
                  <div className="action-body">{act.summary || act.detail || act.message}</div>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ color: '#94a3b8', fontStyle: 'italic' }}>No recorded system actions for this PR.</div>
          )}

          {selected.system_comments && selected.system_comments.length > 0 && (
            <div style={{ marginTop: '1rem' }}>
              <h5 style={{ marginBottom: '0.5rem' }}>Comments added by system</h5>
              <div className="comment-list">
                {selected.system_comments.map((c, idx) => (
                  <div key={idx} className="comment-box">
                    <div className="comment-meta"><strong>System</strong> · <small>{prettyDate(c.created_at)}</small></div>
                    <div className="comment-body">{c.body}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {selected.inferences && selected.inferences.length > 0 && (
            <div style={{ marginTop: '1rem' }}>
              <h5 style={{ marginBottom: '0.5rem' }}>Inferences</h5>
              <ul className="inference-list">
                {selected.inferences.map((inf, idx) => <li key={idx}>{inf}</li>)}
              </ul>
            </div>
          )}

          {selected.actions_summary && (
            <div style={{ marginTop: '1rem' }}>
              <h5 style={{ marginBottom: '0.5rem' }}>Actions Summary</h5>
              <div style={{ color: '#475569' }}>{selected.actions_summary}</div>
            </div>
          )}
        </div>
      </article>
    )
  }

  return (
    <div className="app-shell">
      {renderSidebar()}
      <main className="main-content">
        {/* If not connected, show prominent connect page */}
        {!setup.connected ? (
          <div className="connect-page">
            <div className="connect-card">
              <h1>Connect your GitHub account</h1>
              <p style={{ color: 'var(--text-muted)', marginTop: '0.5rem' }}>Connect to GitHub to view and manage repositories.</p>
              <div style={{ marginTop: '1.25rem', display: 'flex', gap: '1rem' }}>
                <button onClick={startGithubConnect} className="btn btn-primary">Connect to GitHub</button>
                <button onClick={loadSetupStatus} className="btn btn-ghost">Check status</button>
              </div>
            </div>
          </div>
        ) : (
          <>
            {/* If no repo selected, show repo picker */}
            {!repoFilter ? (
              <div className="repo-selection">
                <header className="top-bar">
                  <div className="page-title">
                    <h1>Select a repository</h1>
                    <p>Choose a repository to view its dashboard and PRs.</p>
                  </div>
                </header>

                <section className="repo-grid">
                  {renderRepoGrid()}
                </section>
              </div>
            ) : (
              <>
                {/* Top Header */}
                <header className="top-bar">
                  <div className="page-title">
                    <h1>{repoFilter}</h1>
                    <p>Repository dashboard — PR queue, status and details.</p>
                  </div>

                  <div className="filter-bar">
                    <span style={{ padding: '0.5rem', color: '#94a3b8' }}>🔍</span>
                    <input
                      type="text"
                      placeholder="Filter by repo..."
                      className="search-input"
                      value={filterInput}
                      onChange={(e) => {
                        setFilterInput(e.target.value)
                        setRepoFilter(e.target.value)
                      }}
                    />
                  </div>
                </header>

                {error && (
                  <div className="alert alert-error" style={{ marginBottom: '1.5rem', padding: '1rem', background: '#fee2e2', color: '#991b1b', borderRadius: '0.5rem', border: '1px solid #fecaca' }}>
                    {error}
                    <button onClick={() => setError('')} style={{ float: 'right', background: 'none', border: 'none', cursor: 'pointer', color: 'inherit' }}>✕</button>
                  </div>
                )}

                {/* Stats Grid */}
                <section className="stats-grid">
                  {statCards.map((card) => (
                    <article key={card.key} className="stat-card">
                      <p className="stat-label">{card.label}</p>
                      <strong className="stat-value">
                        {loading.stats ? (
                          <span className="skeleton-text" style={{ display: 'inline-block', width: '2rem', height: '1.5rem', background: '#e2e8f0', borderRadius: '0.25rem' }}></span>
                        ) : (
                          stats?.[card.key]
                        )}
                      </strong>
                    </article>
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
              </>
            )}
          </>
        )}
      </main>
    </div>
  )
}

export default App
