import { useEffect, useMemo, useState, useCallback } from 'react'
import './App.css'

const API_BASE = (import.meta.env.VITE_API_BASE || '').replace(/\/$/, '')

// ── Auth Token Helpers ──────────────────────────────────────────────────────
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

function consumeHashCredentials() {
  const hash = window.location.hash
  if (!hash || !hash.includes('auth_token=')) return null
  const params = new URLSearchParams(hash.substring(1))
  const token = params.get('auth_token')
  const login = params.get('github_login')
  if (!token) return null
  window.history.replaceState(null, '', window.location.pathname + window.location.search)
  return { token, login: login || 'unknown' }
}

// ── API Fetcher ─────────────────────────────────────────────────────────────
async function fetchJson(path, params = {}, options = {}) {
  const query = new URLSearchParams()
  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null || value === '') return
    query.set(key, String(value))
  })
  const url = `${API_BASE}${path}${query.size ? `?${query.toString()}` : ''}`

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
  try { bodyText = await response.text() } catch { throw new Error(`Request failed (${response.status})`) }

  if (!response.ok) {
    let message = `Request failed (${response.status})`
    if (bodyText) {
      try {
        const body = JSON.parse(bodyText)
        message = body.detail || body.message || message
      } catch { message = bodyText }
    }
    throw new Error(message)
  }

  const contentType = response.headers.get('content-type') || ''
  if (!contentType.includes('application/json')) return {}
  if (!bodyText) return {}
  try { return JSON.parse(bodyText) } catch { return {} }
}

// ── Helpers ─────────────────────────────────────────────────────────────────
function prettyDate(isoString) {
  if (!isoString) return '—'
  const date = new Date(isoString)
  if (Number.isNaN(date.getTime())) return '—'
  return date.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

function getVerdictClass(verdict) {
  const v = (verdict || '').toLowerCase()
  if (v === 'passed' || v.includes('approve') || v.includes('legit')) return 'approved'
  if (v === 'failed' || v.includes('spam')) return 'spam'
  if (v === 'soft_fail') return 'spam'
  return 'pending'
}

function getVerdictBadgeClass(verdict) {
  const v = (verdict || '').toLowerCase()
  if (v === 'passed') return 'verdict-passed'
  if (v === 'failed') return 'verdict-failed'
  if (v === 'soft_fail') return 'verdict-soft-fail'
  return 'verdict-pending'
}

function getVerdictIcon(verdict) {
  const v = (verdict || '').toLowerCase()
  if (v === 'passed') return '✓'
  if (v === 'failed') return '✕'
  if (v === 'soft_fail') return '⚠'
  return '◷'
}

// ── GitHub SVG Icon ─────────────────────────────────────────────────────────
function GitHubIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" width="22" height="22">
      <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
    </svg>
  )
}


// ═══════════════════════════════════════════════════════════════════════════
// PAGE 1: Connect to GitHub
// ═══════════════════════════════════════════════════════════════════════════
function ConnectPage({ onConnect, oauthEnabled, error }) {
  function startConnect() {
    const returnTo = `${window.location.origin}${window.location.pathname}${window.location.search}`
    window.location.href = `${API_BASE}/auth/github/start?next=${encodeURIComponent(returnTo)}`
  }

  return (
    <div className="connect-page">
      <div className="connect-card">
        <div className="connect-logo">🛡️</div>
        <h1>Sieve</h1>
        <p className="subtitle">
          Intelligent PR gatekeeper. Connect your GitHub account to start
          filtering pull requests with AI-powered analysis.
        </p>
        <button
          className="github-connect-btn"
          onClick={startConnect}
          disabled={!oauthEnabled}
        >
          <GitHubIcon />
          Connect with GitHub
        </button>

        {!oauthEnabled && (
          <div className="connect-error-msg">
            GitHub OAuth is not configured on the backend. Set <code>GITHUB_OAUTH_CLIENT_ID</code> and <code>GITHUB_OAUTH_CLIENT_SECRET</code>.
          </div>
        )}
        {error && <div className="connect-error-msg">{error}</div>}

        <div className="connect-features">
          <div className="connect-feature">
            <span className="cf-icon">🔍</span>
            <span className="cf-text">AI-powered PR analysis</span>
          </div>
          <div className="connect-feature">
            <span className="cf-icon">🚫</span>
            <span className="cf-text">Auto-close spam PRs</span>
          </div>
          <div className="connect-feature">
            <span className="cf-icon">📊</span>
            <span className="cf-text">Quality & effort scoring</span>
          </div>
        </div>
      </div>
    </div>
  )
}


// ═══════════════════════════════════════════════════════════════════════════
// PAGE 2: Repository List
// ═══════════════════════════════════════════════════════════════════════════
function ReposPage({ githubLogin, onSelectRepo, onDisconnect }) {
  const [repos, setRepos] = useState([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [error, setError] = useState('')

  useEffect(() => {
    async function loadRepos() {
      setLoading(true)
      try {
        // Try the dedicated repos endpoint first
        const data = await fetchJson('/api/repos/list')
        setRepos(data.repositories || [])
        setError('')
      } catch (err) {
        // Fallback: try setup status for visible_repositories
        try {
          const statusData = await fetchJson('/api/setup/status')
          setRepos(statusData.visible_repositories || [])
          setError('')
        } catch (err2) {
          setError(`Could not load repositories: ${err.message}`)
        }
      } finally {
        setLoading(false)
      }
    }
    loadRepos()
  }, [])

  const filteredRepos = useMemo(() => {
    if (!search.trim()) return repos
    const q = search.toLowerCase()
    return repos.filter(r =>
      (r.full_name || '').toLowerCase().includes(q)
    )
  }, [repos, search])

  return (
    <div className="repos-page">
      <header className="repos-topbar">
        <div className="repos-topbar-left">
          <div className="topbar-logo">🛡️</div>
          <span className="topbar-brand">Sieve</span>
        </div>
        <div className="repos-topbar-right">
          <div className="user-chip">
            <span className="avatar-sm">{(githubLogin || '?').charAt(0).toUpperCase()}</span>
            <span>{githubLogin}</span>
          </div>
          <button className="btn-disconnect" onClick={onDisconnect}>Disconnect</button>
        </div>
      </header>

      <div className="repos-content">
        <div className="repos-header">
          <h1>Your Repositories</h1>
          <p>Select a repository to view its PR dashboard and analysis details.</p>
        </div>

        <div className="repos-search-bar">
          <span className="search-icon">🔍</span>
          <input
            type="text"
            placeholder="Search repositories..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
          <span className="repo-count-chip">{filteredRepos.length} repos</span>
        </div>

        {error && (
          <div className="error-banner">
            <span>{error}</span>
            <button onClick={() => setError('')}>✕</button>
          </div>
        )}

        {loading ? (
          <div className="repos-loading">
            <div className="spinner"></div>
            <span>Loading repositories...</span>
          </div>
        ) : filteredRepos.length === 0 ? (
          <div className="repos-empty">
            <div className="empty-icon">📦</div>
            <p>{search ? 'No repositories match your search.' : 'No repositories found. Make sure your GitHub account has accessible repositories.'}</p>
          </div>
        ) : (
          <div className="repos-grid">
            {filteredRepos.map(repo => (
              <div
                key={repo.id || repo.full_name}
                className="repo-card"
                onClick={() => onSelectRepo(repo.full_name)}
              >
                <div className="repo-card-header">
                  <div className="repo-icon">📁</div>
                  <span className={`repo-visibility-badge ${repo.private ? 'private' : 'public'}`}>
                    {repo.private ? '🔒 Private' : '🌐 Public'}
                  </span>
                </div>
                <div className="repo-name">{(repo.full_name || '').split('/')[1] || repo.full_name}</div>
                <div className="repo-owner">{(repo.full_name || '').split('/')[0]}</div>
                <div className="repo-card-footer">
                  <span className="repo-role-badge">{repo.admin ? 'Admin' : 'Collaborator'}</span>
                  {repo.managed && <span className="repo-role-badge repo-managed-badge">Managed</span>}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}


// ═══════════════════════════════════════════════════════════════════════════
// PAGE 3: Repository Dashboard
// ═══════════════════════════════════════════════════════════════════════════
function DashboardPage({ repoFullName, onBack, githubLogin }) {
  const [dashboard, setDashboard] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [activeTab, setActiveTab] = useState('pending')
  const [selectedPR, setSelectedPR] = useState(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [refreshing, setRefreshing] = useState(false)

  const loadDashboard = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    else setRefreshing(true)
    try {
      const data = await fetchJson(`/api/repos/${repoFullName}/dashboard`)
      setDashboard(data)
      setError('')
    } catch (err) {
      setError(`Failed to load dashboard: ${err.message}`)
    } finally {
      if (!silent) setLoading(false)
      setRefreshing(false)
    }
  }, [repoFullName])

  useEffect(() => {
    loadDashboard()
    setSelectedPR(null)
    setActiveTab('pending')
  }, [repoFullName, loadDashboard])

  async function openDetail(scanId) {
    setDetailLoading(true)
    try {
      const data = await fetchJson(`/api/prs/${scanId}`)
      setSelectedPR(data)
    } catch (err) {
      setError(`Detail error: ${err.message}`)
    } finally {
      setDetailLoading(false)
    }
  }

  const stats = dashboard?.stats || {}
  const tabItems = {
    pending: dashboard?.pending || [],
    reviewed: dashboard?.reviewed || [],
    spam_closed: dashboard?.spam_closed || [],
  }
  const currentItems = tabItems[activeTab] || []

  const tabs = [
    { key: 'pending', label: 'In Queue', icon: '⏳', count: stats.queue_pending || 0 },
    { key: 'reviewed', label: 'Approved', icon: '✅', count: stats.reviewed_approved || 0 },
    { key: 'spam_closed', label: 'Spam / Closed', icon: '🚫', count: stats.spam_closed || 0 },
  ]

  return (
    <div className="dashboard-page">
      {/* Top Bar */}
      <header className="dash-topbar">
        <div className="dash-topbar-left">
          <button className="btn-back" onClick={onBack}>
            ← Back
          </button>
          <span className="dash-repo-name">{repoFullName}</span>
        </div>
        <div className="dash-topbar-right">
          <button
            className={`btn-refresh ${refreshing ? 'spinning' : ''}`}
            onClick={() => loadDashboard(true)}
            disabled={refreshing}
          >
            <span className="refresh-icon">↻</span>
            {refreshing ? 'Refreshing...' : 'Refresh'}
          </button>
          <div className="user-chip">
            <span className="avatar-sm">{(githubLogin || '?').charAt(0).toUpperCase()}</span>
            <span>{githubLogin}</span>
          </div>
        </div>
      </header>

      <div className="dash-content">
        {error && (
          <div className="error-banner">
            <span>{error}</span>
            <button onClick={() => setError('')}>✕</button>
          </div>
        )}

        {loading ? (
          <div className="loading-overlay" style={{ minHeight: '50vh' }}>
            <div className="spinner"></div>
            <p>Loading dashboard...</p>
          </div>
        ) : (
          <>
            {/* Stats Row */}
            <div className="stats-row">
              <div className="stat-card pending">
                <div className="stat-label">Pending Review</div>
                <div className="stat-value">{stats.queue_pending ?? 0}</div>
              </div>
              <div className="stat-card approved">
                <div className="stat-label">Approved</div>
                <div className="stat-value">{stats.reviewed_approved ?? 0}</div>
              </div>
              <div className="stat-card spam">
                <div className="stat-label">Spam / Closed</div>
                <div className="stat-value">{stats.spam_closed ?? 0}</div>
              </div>
              <div className="stat-card total">
                <div className="stat-label">Total Scans</div>
                <div className="stat-value">{stats.total_scans ?? 0}</div>
              </div>
            </div>

            {/* Tabs */}
            <div className="dash-tabs">
              {tabs.map(tab => (
                <button
                  key={tab.key}
                  className={`dash-tab ${activeTab === tab.key ? 'active' : ''}`}
                  onClick={() => { setActiveTab(tab.key); setSelectedPR(null) }}
                >
                  {tab.icon} {tab.label}
                  <span className="tab-count">{tab.count}</span>
                </button>
              ))}
            </div>

            {/* Content Split */}
            <div className="dash-split">
              {/* PR List */}
              <div className="pr-list-panel">
                <div className="pr-list-header">
                  <h3>{tabs.find(t => t.key === activeTab)?.label || 'PRs'}</h3>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{currentItems.length} items</span>
                </div>
                <div className="pr-list-scroll">
                  {currentItems.length === 0 ? (
                    <div className="pr-empty-state">
                      <span className="empty-icon">{tabs.find(t => t.key === activeTab)?.icon}</span>
                      <p>No {tabs.find(t => t.key === activeTab)?.label.toLowerCase()} PRs yet.</p>
                    </div>
                  ) : (
                    currentItems.map(item => (
                      <div
                        key={item.id}
                        className={`pr-list-item ${selectedPR?.id === item.id ? 'selected' : ''}`}
                        onClick={() => openDetail(item.id)}
                      >
                        <div className={`pr-item-icon ${getVerdictClass(item.verdict)}`}>
                          {getVerdictIcon(item.verdict)}
                        </div>
                        <div className="pr-item-body">
                          <div className="pr-item-title">#{item.pr_number} {item.pr_title}</div>
                          <div className="pr-item-meta">
                            <span>{item.pr_author || '—'}</span>
                            <span>·</span>
                            <span>{(item.verdict || 'pending').replaceAll('_', ' ')}</span>
                          </div>
                        </div>
                        <div className="pr-item-date">{prettyDate(item.updated_at || item.created_at)}</div>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* PR Detail */}
              <div className="pr-detail-panel">
                {detailLoading ? (
                  <div className="loading-overlay">
                    <div className="spinner"></div>
                    <p>Loading details...</p>
                  </div>
                ) : !selectedPR ? (
                  <div className="pr-detail-placeholder">
                    <span className="placeholder-icon">📋</span>
                    <p>Select a PR from the list to view its analysis details.</p>
                  </div>
                ) : (
                  <>
                    <div className="pr-detail-header">
                      <h2>{selectedPR.pr_title}</h2>
                      <div className="pr-detail-badges">
                        <span className={`detail-badge ${getVerdictBadgeClass(selectedPR.verdict)}`}>
                          {getVerdictIcon(selectedPR.verdict)} {(selectedPR.verdict || 'pending').replaceAll('_', ' ')}
                        </span>
                        <span className="detail-badge neutral">PR #{selectedPR.pr_number}</span>
                        <span className="detail-badge neutral">{selectedPR.pr_author}</span>
                        <span className="detail-badge neutral">{prettyDate(selectedPR.created_at)}</span>
                        {selectedPR.auto_closed && (
                          <span className="detail-badge verdict-failed">Auto-Closed</span>
                        )}
                      </div>
                      {selectedPR.pr_url && (
                        <a
                          href={selectedPR.pr_url}
                          target="_blank"
                          rel="noreferrer"
                          className="pr-detail-link"
                        >
                          View on GitHub ↗
                        </a>
                      )}
                    </div>

                    {selectedPR.analysis && (
                      <>
                        {/* Scores */}
                        <div className="scores-row">
                          <div className="score-tile">
                            <div className="score-label">Spam Score</div>
                            <div className={`score-value ${selectedPR.analysis.spam_score > 50 ? 'danger' : 'success'}`}>
                              {selectedPR.analysis.spam_score ?? '—'}
                            </div>
                          </div>
                          <div className="score-tile">
                            <div className="score-label">Quality Score</div>
                            <div className={`score-value ${(selectedPR.analysis.quality_score || 0) >= 60 ? 'success' : 'warning'}`}>
                              {selectedPR.analysis.quality_score ?? '—'}
                            </div>
                          </div>
                          <div className="score-tile">
                            <div className="score-label">Effort Score</div>
                            <div className={`score-value ${(selectedPR.analysis.effort_score || 0) >= 50 ? 'success' : 'warning'}`}>
                              {selectedPR.analysis.effort_score ?? '—'}
                            </div>
                          </div>
                        </div>

                        {/* Verdict Reason */}
                        {selectedPR.analysis.verdict_reason && (
                          <div className="analysis-section">
                            <h4>💬 Verdict Reason</h4>
                            <p>{selectedPR.analysis.verdict_reason}</p>
                          </div>
                        )}

                        {/* Spam Reason */}
                        {selectedPR.analysis.spam_reason && (
                          <div className="analysis-section">
                            <h4>🚫 Spam Reason</h4>
                            <p>{selectedPR.analysis.spam_reason}</p>
                          </div>
                        )}

                        {/* Issue Alignment */}
                        {selectedPR.analysis.issue_alignment_reason && (
                          <div className="analysis-section">
                            <h4>🎯 Issue Alignment</h4>
                            <p>
                              {selectedPR.analysis.issue_aligned ? '✓ Aligned' : '✕ Not aligned'}
                              {selectedPR.analysis.issue_number && ` with issue #${selectedPR.analysis.issue_number}`}
                              {selectedPR.analysis.issue_alignment_score != null && ` (score: ${selectedPR.analysis.issue_alignment_score})`}
                              {' — '}
                              {selectedPR.analysis.issue_alignment_reason}
                            </p>
                          </div>
                        )}

                        {/* Description Match */}
                        {selectedPR.analysis.description_match_reason && (
                          <div className="analysis-section">
                            <h4>📝 Description Match</h4>
                            <p>
                              {selectedPR.analysis.description_match ? '✓ Matches' : '✕ Mismatch'}
                              {selectedPR.analysis.description_match_score != null && ` (score: ${selectedPR.analysis.description_match_score})`}
                              {' — '}
                              {selectedPR.analysis.description_match_reason}
                            </p>
                          </div>
                        )}

                        {/* Quality Issues */}
                        {selectedPR.analysis.quality_issues?.length > 0 && (
                          <div className="analysis-section">
                            <h4>⚠️ Quality Issues</h4>
                            <div className="analysis-tags">
                              {selectedPR.analysis.quality_issues.map((issue, i) => (
                                <span key={i} className="analysis-tag">{issue}</span>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Policy Violations */}
                        {selectedPR.analysis.policy_violations?.length > 0 && (
                          <div className="analysis-section">
                            <h4>🛑 Policy Violations</h4>
                            <div className="analysis-tags">
                              {selectedPR.analysis.policy_violations.map((v, i) => (
                                <span key={i} className="analysis-tag policy">{v}</span>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Additional Metrics */}
                        {(selectedPR.analysis.author_account_age_days != null || selectedPR.analysis.signal_to_noise_ratio != null) && (
                          <div className="analysis-section">
                            <h4>📊 Additional Metrics</h4>
                            <div className="scores-row" style={{ gridTemplateColumns: '1fr 1fr' }}>
                              {selectedPR.analysis.author_account_age_days != null && (
                                <div className="score-tile">
                                  <div className="score-label">Author Age (days)</div>
                                  <div className="score-value">{selectedPR.analysis.author_account_age_days}</div>
                                </div>
                              )}
                              {selectedPR.analysis.signal_to_noise_ratio != null && (
                                <div className="score-tile">
                                  <div className="score-label">Signal/Noise</div>
                                  <div className="score-value">{selectedPR.analysis.signal_to_noise_ratio}</div>
                                </div>
                              )}
                            </div>
                          </div>
                        )}
                      </>
                    )}
                  </>
                )}
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  )
}


// ═══════════════════════════════════════════════════════════════════════════
// APP — Page Router
// ═══════════════════════════════════════════════════════════════════════════
function App() {
  // 'connect' | 'repos' | 'dashboard'
  const [page, setPage] = useState('connect')
  const [githubLogin, setGithubLogin] = useState('')
  const [oauthEnabled, setOauthEnabled] = useState(true)
  const [selectedRepo, setSelectedRepo] = useState(null)
  const [error, setError] = useState('')
  const [initialLoading, setInitialLoading] = useState(true)

  // On mount: check for hash credentials, then check setup status
  useEffect(() => {
    async function init() {
      // 1) Try consuming OAuth hash from redirect
      const creds = consumeHashCredentials()
      if (creds) {
        saveAuthCredentials(creds.token, creds.login)
        setGithubLogin(creds.login)
        setPage('repos')
        setInitialLoading(false)
        return
      }

      // 2) Try saved credentials
      const savedToken = getSavedAuthToken()
      const savedLogin = getSavedGithubLogin()
      if (savedToken && savedLogin) {
        // Verify the token is still valid
        try {
          const data = await fetchJson('/api/setup/status')
          setOauthEnabled(data.oauth_enabled !== false)
          if (data.connected) {
            setGithubLogin(data.github_login || savedLogin)
            setPage('repos')
          } else {
            // Token invalid, clear
            clearAuthCredentials()
            setPage('connect')
          }
        } catch {
          // Backend unreachable; use saved creds anyway
          setGithubLogin(savedLogin)
          setPage('repos')
        }
        setInitialLoading(false)
        return
      }

      // 3) Not connected, check if oauth is enabled
      try {
        const data = await fetchJson('/api/setup/status')
        setOauthEnabled(data.oauth_enabled !== false)
      } catch {
        // Backend may be down
      }
      setPage('connect')
      setInitialLoading(false)
    }
    init()
  }, [])

  function handleDisconnect() {
    clearAuthCredentials()
    fetchJson('/api/setup/logout', {}, { method: 'POST' }).catch(() => { })
    setGithubLogin('')
    setSelectedRepo(null)
    setPage('connect')
  }

  function handleSelectRepo(repoFullName) {
    setSelectedRepo(repoFullName)
    setPage('dashboard')
  }

  function handleBackToRepos() {
    setSelectedRepo(null)
    setPage('repos')
  }

  if (initialLoading) {
    return (
      <div className="connect-page">
        <div className="loading-overlay">
          <div className="spinner"></div>
          <p style={{ color: 'var(--text-muted)' }}>Loading Sieve...</p>
        </div>
      </div>
    )
  }

  if (page === 'connect') {
    return <ConnectPage oauthEnabled={oauthEnabled} error={error} onConnect={() => { }} />
  }

  if (page === 'repos') {
    return (
      <ReposPage
        githubLogin={githubLogin}
        onSelectRepo={handleSelectRepo}
        onDisconnect={handleDisconnect}
      />
    )
  }

  if (page === 'dashboard' && selectedRepo) {
    return (
      <DashboardPage
        repoFullName={selectedRepo}
        onBack={handleBackToRepos}
        githubLogin={githubLogin}
      />
    )
  }

  return <ConnectPage oauthEnabled={oauthEnabled} error={error} onConnect={() => { }} />
}

export default App
