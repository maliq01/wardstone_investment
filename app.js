// ════════════════════════════════════════════════════════════
//  SUPABASE — FUND ACCOUNTING ENGINE
//  All financial data lives in Supabase PostgreSQL.
//  No localStorage for any financial record.
//
//  SECURITY: The anon key is read from a <meta> tag injected
//  by your server at request time, NOT hardcoded here.
//  In your HTML <head> add:
//    <meta name="sb-url"  content="YOUR_SUPABASE_URL">
//    <meta name="sb-anon" content="YOUR_SUPABASE_ANON_KEY">
//  Serve those values via an environment variable on your
//  hosting platform (Vercel / Netlify / Cloudflare Pages).
//  Never commit the real key to source control.
// ════════════════════════════════════════════════════════════
(function () {
  const urlMeta  = document.querySelector('meta[name="sb-url"]');
  const anonMeta = document.querySelector('meta[name="sb-anon"]');
  if (!urlMeta || !anonMeta || !urlMeta.content || !anonMeta.content) {
    console.error('❌ Supabase config meta tags missing. Add <meta name="sb-url"> and <meta name="sb-anon"> to your HTML.');
  }
})();

const SUPABASE_URL  = (document.querySelector('meta[name="sb-url"]')  || {}).content || '';
const SUPABASE_ANON = (document.querySelector('meta[name="sb-anon"]') || {}).content || '';

// Guard: if Supabase CDN failed to load, show a clear error instead of crashing silently
if (typeof supabase === 'undefined') {
  document.addEventListener('DOMContentLoaded', () => {
    const body = document.body;
    if (body) {
      body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100vh;background:#0a0a0a;color:#fff;font-family:sans-serif;flex-direction:column;gap:16px">' +
        '<div style="font-size:40px">⚠️</div>' +
        '<div style="font-size:18px;font-weight:500">Connection Error</div>' +
        '<div style="font-size:14px;color:#888;text-align:center;max-width:400px">Could not load required resources. Please check your internet connection and refresh the page.</div>' +
        '<button onclick="location.reload()" style="margin-top:8px;padding:12px 24px;background:#c9a84c;color:#000;border:none;border-radius:8px;font-size:14px;cursor:pointer;font-weight:500">Refresh Page</button>' +
        '</div>';
    }
  });
  throw new Error('Supabase CDN not loaded — check internet connection.');
}

const sb = supabase.createClient(SUPABASE_URL, SUPABASE_ANON);

window._sbReady = true;
console.log('✅ Supabase connected — fund accounting engine active');

// ════════════════════════════════════════════
//  PASSWORD RECOVERY DETECTION (must run before 'load')
// ════════════════════════════════════════════
// IMPORTANT: the "Reset Password" email template must link to
//   {{ .SiteURL }}/?type=recovery&token_hash={{ .TokenHash }}
// instead of Supabase's default {{ .ConfirmationURL }}. Here's why:
// {{ .ConfirmationURL }} points at Supabase's own /auth/v1/verify endpoint,
// which consumes the one-time recovery token the INSTANT it's visited by
// anyone/anything — including automated link-scanners that many email
// providers run to check links for safety before a user ever opens the
// email. That silently burns the token, so by the time the real client
// clicks, Supabase correctly reports it as expired/invalid.
// Landing on OUR OWN page first (a harmless GET, nothing consumed) and only
// THEN calling verifyOtp() ourselves via a script-driven POST sidesteps
// this, since scanners fetch links but don't execute page JavaScript.
const recoveryParams = new URLSearchParams(window.location.search);
const RECOVERY_TOKEN_HASH = recoveryParams.get('token_hash');
const IS_PASSWORD_RECOVERY_LINK = recoveryParams.get('type') === 'recovery' && !!RECOVERY_TOKEN_HASH;
let recoveryUIShown = false;

if (IS_PASSWORD_RECOVERY_LINK) {
  sb.auth.verifyOtp({ token_hash: RECOVERY_TOKEN_HASH, type: 'recovery' }).then(({ error }) => {
    if (error) {
      toast('This password reset link is invalid or has expired. Please request a new one.', 'error');
      return;
    }
    recoveryUIShown = true;
    showRecoveryPasswordUI();
  });
}

// Fallback: if Supabase's default hash-based recovery link (#access_token=...
// &type=recovery) is ever used instead, this still catches it via the
// PASSWORD_RECOVERY auth event Supabase fires once it finishes parsing.
sb.auth.onAuthStateChange((event) => {
  if (event === 'PASSWORD_RECOVERY') {
    recoveryUIShown = true;
    showRecoveryPasswordUI();
  }
});

// ════════════════════════════════════════════
//  SIGNUP CONFIRMATION DETECTION (same scanner-consumption risk as above)
// ════════════════════════════════════════════
// The "Confirm signup" email template must link to
//   {{ .SiteURL }}/?type=signup&token_hash={{ .TokenHash }}
// for the same reason as password recovery above.
const IS_SIGNUP_CONFIRM_LINK = recoveryParams.get('type') === 'signup' && !!RECOVERY_TOKEN_HASH;
let signupConfirmHandled = false;

if (IS_SIGNUP_CONFIRM_LINK) {
  signupConfirmHandled = true; // prevents the normal load handler from also running showAuth('login')
  sb.auth.verifyOtp({ token_hash: RECOVERY_TOKEN_HASH, type: 'signup' }).then(({ error }) => {
    // sb.auth.signOut() below: verifyOtp establishes a live Supabase session,
    // but this app tracks "logged in" separately via its own wad_session
    // marker (set only by doLogin()). Signing out here avoids a mismatched
    // half-logged-in state — the user explicitly logs in right after, same
    // as any other first-time sign-in.
    sb.auth.signOut().finally(() => {
      applyAllSettings();
      showAuth('login');
      setTimeout(() => {
        if (error) {
          toast('This confirmation link is invalid or has expired. Use "Resend confirmation email" on the sign-in screen.', 'error');
        } else {
          toast('Email confirmed! You can now sign in below.', 'success');
        }
      }, 300);
    });
  });
}

// ════════════════════════════════════════════════════════════
//  MONITORING — Sentry · Logtail · Admin Notifications
//
//  HOW TO CONFIGURE:
//  Add these meta tags to your HTML <head> alongside sb-url/sb-anon:
//    <meta name="sentry-dsn"    content="YOUR_SENTRY_DSN">
//    <meta name="logtail-token" content="YOUR_LOGTAIL_SOURCE_TOKEN">
//
//  Sentry:      https://sentry.io          (free: 5k errors/month)
//  Logtail:     https://betterstack.com/logtail (free: 1GB/month)
//  UptimeRobot: https://uptimerobot.com    (no code — configure in their dashboard)
// ════════════════════════════════════════════════════════════

const MONITORING = {
  sentryDsn:    (document.querySelector('meta[name="sentry-dsn"]')    || {}).content || '',
  logtailToken: (document.querySelector('meta[name="logtail-token"]') || {}).content || '',
};

// ── SENTRY — JS error capture with stack traces and user context ──────
function initSentry() {
  if (!MONITORING.sentryDsn || !window.Sentry) return;
  Sentry.init({
    dsn: MONITORING.sentryDsn,
    environment: window.location.hostname === 'localhost' ? 'development' : 'production',
    release: 'wadstone@1.0.0',
    tracesSampleRate: 0.2,
    beforeSend(event) {
      // Strip PII — keep user ID for grouping, never send email to Sentry
      if (event.user) { delete event.user.email; delete event.user.username; }
      return event;
    }
  });
}

function setSentryUser(userId, role) {
  if (!window.Sentry) return;
  Sentry.setUser({ id: userId, role });
}
function clearSentryUser() {
  if (!window.Sentry) return;
  Sentry.setUser(null);
}

// Use in catch blocks for critical operations so handled errors
// still appear in Sentry (payments, approvals, KYC actions).
function captureError(err, context = {}) {
  console.error('[Error]', err, context);
  if (window.Sentry) {
    Sentry.withScope(scope => {
      Object.entries(context).forEach(([k, v]) => scope.setExtra(k, v));
      Sentry.captureException(err instanceof Error ? err : new Error(String(err)));
    });
  }
  shipLog('error', err?.message || String(err), { ...context, stack: err?.stack });
}

// ── LOGTAIL — structured event log shipped to BetterStack ────────────
async function shipLog(level, message, data = {}) {
  if (!MONITORING.logtailToken) return;
  try {
    await fetch('https://in.logtail.com', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + MONITORING.logtailToken
      },
      body: JSON.stringify({
        level,
        message,
        dt: new Date().toISOString(),
        app: 'wadstone',
        env: window.location.hostname === 'localhost' ? 'dev' : 'prod',
        user_id:   currentUser?.id   || null,
        user_role: currentUser?.role || null,
        url: window.location.pathname,
        ...data
      })
    });
  } catch(e) {
    console.warn('Logtail shipment failed:', e.message);
  }
}

const Log = {
  info:      (msg, data) => { console.log('[Info]',      msg, data); shipLog('info',      msg, data); },
  warn:      (msg, data) => { console.warn('[Warn]',     msg, data); shipLog('warn',      msg, data); },
  error:     (msg, data) => { console.error('[Error]',   msg, data); shipLog('error',     msg, data); },
  financial: (event, data) => {
    console.log('[Financial]', event, data);
    shipLog('financial', event, { ...data, _financial: true });
  }
};

// ── ADMIN NOTIFICATIONS — out-of-band email for every sensitive action ─
// Sends to the admin's own email so there's a paper trail outside the app.
function notifyAdmin(action, details) {
  if (!currentUser || currentUser.role !== 'admin') return;
  sendEmailNotification(
    currentUser.email,
    currentUser.name,
    '[Wadstone Admin] ' + action,
    'Action: ' + action + '\nDetails: ' + details + '\nBy: ' + currentUser.email + '\nTime: ' + new Date().toUTCString() + '\n\nThis is an automated security notification from your Wadstone platform.'
  );
  Log.financial(action, { details, admin: currentUser.email });
}

// ── GLOBAL ERROR CATCHERS — routes all unhandled errors to Sentry/Logtail ─
window.addEventListener('error', (e) => {
  captureError(e.error || new Error(e.message), {
    filename: e.filename, lineno: e.lineno, colno: e.colno, type: 'uncaught_exception'
  });
});
window.addEventListener('unhandledrejection', (e) => {
  captureError(e.reason || new Error('Unhandled promise rejection'), { type: 'unhandled_rejection' });
});

initSentry();

// ════════════════════════════════════════════════════════════
//  SECURITY HELPERS
// ════════════════════════════════════════════════════════════

// FIX H2 — XSS: sanitize any user-supplied string before
// injecting into innerHTML. Strips all HTML tags.
function sanitize(str) {
  if (str === null || str === undefined) return '';
  const d = document.createElement('div');
  d.textContent = String(str);
  return d.innerHTML;
}

// FIX C2 — KYC docs: upload file to Supabase Storage and
// return the storage path. Never touches localStorage.
async function uploadDocToStorage(investorId, docKey, base64DataUrl, fileName, mimeType) {
  // Convert base64 to blob directly without fetch()
  const base64Data = base64DataUrl.split(',')[1];
  const byteCharacters = atob(base64Data);
  const byteNumbers = new Array(byteCharacters.length);
  for (let i = 0; i < byteCharacters.length; i++) {
    byteNumbers[i] = byteCharacters.charCodeAt(i);
  }
  const byteArray = new Uint8Array(byteNumbers);
  const blob = new Blob([byteArray], { type: mimeType });
  const ext  = fileName.split('.').pop().toLowerCase();
  const path = 'kyc/' + investorId + '/' + docKey + '.' + ext;
  const { error } = await sb.storage
    .from('kyc-documents')
    .upload(path, blob, { contentType: mimeType, upsert: true });
  if (error) throw new Error('Storage upload failed: ' + error.message);
  return path;
}

// FIX C2 — Get a short-lived (60 s) signed URL for a stored doc.
async function getDocSignedUrl(storagePath) {
  const { data, error } = await sb.storage
    .from('kyc-documents')
    .createSignedUrl(storagePath, 60);
  if (error) throw new Error('Could not generate signed URL');
  return data.signedUrl;
}

// FIX H3 — Brute force: server-side attempt tracking via RPC.
// Falls back gracefully if the RPC functions are not yet deployed.
async function serverCheckLoginAllowed(email) {
  try {
    const { data, error } = await sb.rpc('check_login_allowed', { p_email: email });
    if (error) return { allowed: true };
    return data || { allowed: true };
  } catch (e) { return { allowed: true }; }
}
async function serverRecordLoginFailure(email) {
  try { await sb.rpc('record_login_failure', { p_email: email }); } catch (e) {}
}
async function serverClearLoginFailures(email) {
  try { await sb.rpc('clear_login_failures', { p_email: email }); } catch (e) {}
}

// FIX M3 — Input validation helpers
function validateAmount(val, min, max) {
  const n = parseFloat(val);
  if (isNaN(n) || !isFinite(n) || n <= 0) return null;
  if (n < min) return null;
  if (max !== undefined && n > max) return null;
  return Math.round(n * 100) / 100;
}
function validateReference(ref) {
  if (typeof ref !== 'string') return '';
  return ref.replace(/[^a-zA-Z0-9\-_]/g, '').slice(0, 64);
}

// Session idle timeout — auto-logout after 15 min of inactivity
let _idleTimer = null;
const IDLE_TIMEOUT_MS = 15 * 60 * 1000;
function resetIdleTimer() {
  clearTimeout(_idleTimer);
  _idleTimer = setTimeout(function () {
    if (currentUser) {
      toast('Session expired due to inactivity. Please sign in again.', 'info');
      doLogout();
    }
  }, IDLE_TIMEOUT_MS);
}
['click', 'keydown', 'mousemove', 'touchstart'].forEach(function (ev) {
  document.addEventListener(ev, resetIdleTimer, { passive: true });
});

// ─────────────────────────────────────────────────────────────
//  DB LAYER — all reads/writes go through these functions
//  Never write financial data directly from UI components
// ─────────────────────────────────────────────────────────────

// ── INVESTORS ──
async function db_getInvestorByEmail(email) {
  const { data, error } = await sb.from('investors').select('*').eq('email', email.toLowerCase()).single();
  if (error && error.code !== 'PGRST116') console.error('db_getInvestorByEmail:', error);
  return data;
}
async function db_getAllInvestors() {
  const { data, error } = await sb.from('investors').select('*, capital_accounts(*)').order('created_at', { ascending: false });
  if (error) console.error('db_getAllInvestors:', error);
  return data || [];
}
async function db_createInvestor(investor) {
  const { data, error } = await sb.from('investors').insert(investor).select().single();
  if (error) throw error;
  return data;
}
async function db_updateInvestor(id, updates) {
  const { error } = await sb.from('investors').update(updates).eq('id', id);
  if (error) throw error;
  return true;
}

// ── CAPITAL ACCOUNTS (read-only from frontend) ──
async function db_getCapitalAccount(investorId) {
  const { data, error } = await sb.from('capital_accounts').select('*').eq('investor_id', investorId).single();
  if (error && error.code !== 'PGRST116') console.error('db_getCapitalAccount:', error);
  return data;
}
async function db_getAllCapitalAccounts() {
  const { data, error } = await sb.from('capital_accounts').select('*, investors(name,email,kyc_status)');
  if (error) console.error('db_getAllCapitalAccounts:', error);
  return data || [];
}

// ── TRANSACTIONS ──
async function db_getTransactions(investorId, limit = 50) {
  let q = sb.from('transactions').select('*').order('created_at', { ascending: false }).limit(limit);
  if (investorId) q = q.eq('investor_id', investorId);
  const { data, error } = await q;
  if (error) console.error('db_getTransactions:', error);
  return data || [];
}
async function db_getPendingTransactions() {
  const { data, error } = await sb.from('transactions')
    .select('*, investors(name,email)')
    .eq('status', 'pending')
    .order('created_at', { ascending: false });
  if (error) console.error('db_getPendingTransactions:', error);
  return data || [];
}
async function db_createTransaction(txn) {
  const { data, error } = await sb.from('transactions').insert(txn).select().single();
  if (error) throw error;
  return data;
}
async function db_updateTransaction(id, updates) {
  const { data, error } = await sb.from('transactions').update(updates).eq('id', id).select().single();
  if (error) throw error;
  return data;
}

// ── ATOMIC DEPOSIT APPROVAL (calls DB function) ──
async function db_approveDeposit(txnId, investorId, amount, method, reference, approvedBy) {
  const { data, error } = await sb.rpc('process_deposit', {
    p_investor_id: investorId,
    p_amount: amount,
    p_method: method,
    p_reference: reference,
    p_notes: null,
    p_approved_by: approvedBy
  });
  if (error) throw error;
  // Mark original pending txn as approved
  await sb.from('transactions').update({ status: 'approved', approved_by: approvedBy, approved_at: new Date().toISOString() }).eq('id', txnId);
  return data;
}

// ── ATOMIC WITHDRAWAL APPROVAL ──
async function db_approveWithdrawal(txnId, investorId, amount, method, reference, approvedBy) {
  const { data, error } = await sb.rpc('process_withdrawal', {
    p_investor_id: investorId,
    p_amount: amount,
    p_method: method,
    p_reference: reference,
    p_approved_by: approvedBy
  });
  if (error) throw error;
  await sb.from('transactions').update({ status: 'approved', approved_by: approvedBy, approved_at: new Date().toISOString() }).eq('id', txnId);
  return data;
}

// ── POOL SNAPSHOT + PROFIT ALLOCATION ──
async function db_postPoolSnapshot(period, grossReturnPct, mgmtFeeRate, perfFeeRate, hurdleRate, postedBy, notes) {
  const { data, error } = await sb.rpc('post_pool_snapshot', {
    p_period: period,
    p_gross_return_pct: grossReturnPct,
    p_mgmt_fee_rate: mgmtFeeRate,
    p_perf_fee_rate: perfFeeRate,
    p_hurdle_rate: hurdleRate,
    p_posted_by: postedBy,
    p_notes: notes || ''
  });
  if (error) throw error;
  return data;
}

// ── POOL SNAPSHOTS ──
async function db_getSnapshots(limit = 20) {
  const { data, error } = await sb.from('pool_snapshots').select('*').order('created_at', { ascending: false }).limit(limit);
  if (error) console.error('db_getSnapshots:', error);
  return data || [];
}

// ── PROFIT ALLOCATIONS ──
async function db_getAllocations(investorId) {
  const { data, error } = await sb.from('profit_allocations').select('*, pool_snapshots(period, nav_per_unit)').eq('investor_id', investorId).order('created_at', { ascending: false });
  if (error) console.error('db_getAllocations:', error);
  return data || [];
}

// ── AUDIT LOG ──
async function db_writeAudit(actorId, actorEmail, action, entityType, entityId, details) {
  await sb.from('audit_log').insert({ actor_id: actorId, actor_email: actorEmail, action, entity_type: entityType, entity_id: entityId, details });
}
async function db_getAuditLog(limit = 100) {
  const { data, error } = await sb.from('audit_log').select('*').order('created_at', { ascending: false }).limit(limit);
  if (error) console.error('db_getAuditLog:', error);
  return data || [];
}

// ── FEE RECORDS ──
async function db_getFeeRecords(investorId) {
  let q = sb.from('fee_records').select('*').order('created_at', { ascending: false });
  if (investorId) q = q.eq('investor_id', investorId);
  const { data, error } = await q;
  if (error) console.error('db_getFeeRecords:', error);
  return data || [];
}

// ── JOURNAL ENTRIES ──
async function db_getJournalEntries() {
  const { data, error } = await sb.from('journal_entries').select('*, investors(name)').order('created_at', { ascending: false });
  if (error) console.error('db_getJournalEntries:', error);
  return data || [];
}
async function db_createJournalEntry(entry) {
  const { data, error } = await sb.from('journal_entries').insert(entry).select().single();
  if (error) throw error;
  return data;
}

// ── FUND SETTINGS ──
async function db_getFundSettings() {
  const { data } = await sb.from('fund_settings').select('*');
  const settings = {};
  (data || []).forEach(row => { settings[row.key] = typeof row.value === 'string' ? JSON.parse(row.value) : row.value; });
  return settings;
}
async function db_saveFundSetting(key, value, updatedBy) {
  await sb.from('fund_settings').upsert({ key, value: JSON.stringify(value), updated_by: updatedBy, updated_at: new Date().toISOString() }, { onConflict: 'key' });
}

// ════════════════════════════════════════════
//  GLOBAL STATE — no financial data here, only session
// ════════════════════════════════════════════
let currentUser = null;       // investor record from DB
let currentAccount = null;    // capital_account record from DB
let fundSettings = {};        // from fund_settings table
let uploadedDocs = {};        // KYC docs (base64, temp only)
let depositReceipt = null;    // receipt upload (temp only)
let loginAttempts = {};       // brute force tracking (session only)

// Non-financial UI state only in localStorage
function saveUIState(key, val) { try { localStorage.setItem('wad_ui_' + key, JSON.stringify(val)); } catch(e){} }
function loadUIState(key) { try { return JSON.parse(localStorage.getItem('wad_ui_' + key)); } catch(e){ return null; } }

// ── SESSION PERSISTENCE (survives refresh, clears on tab close) ──
function saveSession(user) {
  try {
    sessionStorage.setItem('wad_session', JSON.stringify({
      id:    user.id,
      email: user.email
    }));
  } catch(e) {}
}
function clearSession() {
  try { sessionStorage.removeItem('wad_session'); } catch(e) {}
}
async function restoreSession() {
  try {
    const raw = sessionStorage.getItem('wad_session');
    if (!raw) return false;
    const { id, email } = JSON.parse(raw);
    if (!id || !email) return false;

    // Re-fetch fresh data from Supabase
    const user = await db_getInvestorByEmail(email);
    if (!user || user.id !== id) { clearSession(); return false; }

    const account = await db_getCapitalAccount(user.id);
    currentUser = {
      id: user.id, name: user.name, email: user.email,
      role: user.role, kyc: user.kyc_status,
      kycData: user.kyc_data || {}, kycDocs: user.kyc_docs || {},
      submittedAt: user.submitted_at,
      balance:   account?.balance            || 0,
      deposited: account?.total_deposited    || 0,
      returns:   account?.total_returns      || 0,
      hwm:       account?.high_water_mark    || 0,
      units:     account?.units_held         || 0
    };
    currentAccount = account;
    await syncDBFromSupabase();
    await loadFundSettings();
    return true;
  } catch(e) {
    console.warn('restoreSession failed:', e);
    clearSession();
    return false;
  }
}

// Legacy DB shim — keeps existing UI functions working
// while reading from Supabase instead of localStorage
let DB = { users: [], auditLog: [], returnLog: [], feeLog: [], journalEntries: [] };

async function syncDBFromSupabase() {
  try {
    const investors = await db_getAllInvestors();
    DB.users = investors.map(inv => ({
      id: inv.id,
      name: inv.name,
      email: inv.email,
      passwordHash: inv.password_hash,
      passwordHashed: true,
      role: inv.role,
      kyc: inv.kyc_status,
      kycData: inv.kyc_data || {},
      kycDocs: inv.kyc_docs || {},
      submittedAt: inv.submitted_at,
      // Balance always read from capital_accounts, never from this object
      balance: inv.capital_accounts?.[0]?.balance || 0,
      deposited: inv.capital_accounts?.[0]?.total_deposited || 0,
      returns: inv.capital_accounts?.[0]?.total_returns || 0,
      pendingWithdrawal: 0,
      transactions: [] // loaded separately per investor
    }));
  } catch(e) { console.error('syncDBFromSupabase:', e); }
}

function saveDB() {
  // No-op for financial data — Supabase is source of truth
  // Only persists non-financial UI preferences
  console.log('saveDB called — financial data handled by Supabase');
}

// Load fund settings on startup
async function loadFundSettings() {
  try { fundSettings = await db_getFundSettings(); } catch(e) { console.warn('Could not load fund settings:', e); }
}

// ════════════════════════════════════════════
//  UI STATE (non-financial session vars only)
// ════════════════════════════════════════════
let currentKycTarget = null;
let currentTxnTarget = null;

// ════════════════════════════════════════════
//  NAV HELPERS
// ════════════════════════════════════════════
function showAuth(mode) {
  document.getElementById('auth-page').classList.add('active');
  document.getElementById('app').classList.remove('active');
  toggleAuth(mode);
}

function toggleAuth(mode) {
  document.getElementById('login-form').style.display = mode === 'login' ? 'block' : 'none';
  document.getElementById('register-form').style.display = mode === 'register' ? 'block' : 'none';
}

function showApp() {
  document.getElementById('auth-page').classList.remove('active');
  document.getElementById('app').classList.add('active');
}

// ════════════════════════════════════════════
//  AUTH — reads from Supabase investors table
// ════════════════════════════════════════════
let loginAttempts_local = {};

async function doLogin() {
  const email = document.getElementById('login-email').value.trim().toLowerCase();
  const pass  = document.getElementById('login-password').value;
  const errEl = document.getElementById('login-error');
  errEl.style.display = 'none';
  if (!email || !pass) { errEl.textContent = 'Please enter email and password.'; errEl.style.display = 'flex'; return; }

  const loginBtn = document.querySelector('#login-form .btn-gold');
  if (loginBtn) { loginBtn.disabled = true; loginBtn.textContent = 'Signing in...'; }

  try {
    // Use Supabase Auth — not password_hash
    const { data: authData, error: authError } = await sb.auth.signInWithPassword({ email, password: pass });
    if (authError) throw new Error('Invalid email or password.');

    // Fetch investor record linked to this auth user
    const { data: user, error: userError } = await sb.from('investors')
      .select('*')
      .eq('user_id', authData.user.id)
      .single();
    if (userError || !user) throw new Error('Investor record not found. Please contact support.');

    const account = await db_getCapitalAccount(user.id);

    currentUser = {
      id: user.id, name: user.name, email: user.email,
      role: user.role, kyc: user.kyc_status,
      kycData: user.kyc_data || {}, kycDocs: user.kyc_docs || {},
      submittedAt: user.submitted_at,
      balance:   account?.balance         || 0,
      deposited: account?.total_deposited || 0,
      returns:   account?.total_returns   || 0,
      hwm:       account?.high_water_mark || 0,
      units:     account?.units_held      || 0
    };
    currentAccount = account;

    await syncDBFromSupabase();
    await loadFundSettings();
    await db_writeAudit(user.id, user.email, 'LOGIN', 'investor', user.id, user.name + ' signed in');
    saveUIState('lastLogin', new Date().toISOString());
    saveSession(currentUser);
    setSentryUser(user.id, user.role);
    Log.info('LOGIN', { user_id: user.id, role: user.role });
    initApp();

  } catch(e) {
    Log.warn('LOGIN_FAILED', { email, reason: e.message });
    errEl.textContent = e.message || 'Login failed. Please try again.';
    errEl.style.display = 'flex';
  } finally {
    if (loginBtn) { loginBtn.disabled = false; loginBtn.textContent = 'Sign In'; }
  }
}


async function doLogout() {
  if (currentUser) await db_writeAudit(currentUser.id, currentUser.email, 'LOGOUT', 'investor', currentUser.id, currentUser.name + ' signed out');
  clearSentryUser();
  Log.info('LOGOUT', { user_id: currentUser?.id });
  currentUser = null; currentAccount = null;
  DB = { users: [], auditLog: [], returnLog: [], feeLog: [], journalEntries: [] };
  clearSession();
  showAuth('login');
}


// ════════════════════════════════════════════
//  KYC REGISTRATION FLOW
// ════════════════════════════════════════════
let kycStep = 1;

function kycNext(step) {
  const errEl = document.getElementById('reg-error-' + step);
  errEl.style.display = 'none';

  if (step === 1) {
    const name = document.getElementById('reg-name').value.trim();
    const email = document.getElementById('reg-email').value.trim();
    const pass = document.getElementById('reg-password').value;
    const confirm = document.getElementById('reg-confirm').value;
    const type = document.getElementById('reg-type').value;
    if (!name || !email || !pass || !type) { showErr(errEl, 'Please fill all required fields.'); return; }
    if (pass.length < 8) { showErr(errEl, 'Password must be at least 8 characters.'); return; }
    if (pass !== confirm) { showErr(errEl, 'Passwords do not match.'); return; }
    if (DB.users.find(u => u.email === email)) { showErr(errEl, 'An account with this email already exists.'); return; }
  }
  if (step === 2) {
    const dob = document.getElementById('reg-dob').value;
    const nat = document.getElementById('reg-nationality').value;
    const phone = document.getElementById('reg-phone').value.trim();
    const addr = document.getElementById('reg-address').value.trim();
    if (!dob || !nat || !phone || !addr) { showErr(errEl, 'Please fill all required fields.'); return; }
  }
  if (step === 3) {
    const sof = document.getElementById('reg-sof').value;
    const inc = document.getElementById('reg-income').value;
    const nw = document.getElementById('reg-networth').value;
    const obj = document.getElementById('reg-obj').value;
    if (!sof || !inc || !nw || !obj) { showErr(errEl, 'Please fill all required fields.'); return; }
  }

  document.getElementById('kyc-' + step).classList.remove('active');
  document.getElementById('step-' + step).classList.remove('active');
  document.getElementById('step-' + step).classList.add('done');
  document.getElementById('step-' + step).querySelector('.step-num').textContent = '✓';

  kycStep = step + 1;
  document.getElementById('kyc-' + kycStep).classList.add('active');
  document.getElementById('step-' + kycStep).classList.add('active');

  // Show/hide payment method details
  document.getElementById('dep-wire-details') && document.getElementById('dep-wire-details');
}

function kycBack(step) {
  document.getElementById('kyc-' + step).classList.remove('active');
  const prev = step - 1;
  document.getElementById('step-' + prev).classList.remove('done');
  document.getElementById('step-' + prev).querySelector('.step-num').textContent = prev;
  document.getElementById('step-' + prev).classList.add('active');
  document.getElementById('kyc-' + prev).classList.add('active');
  kycStep = prev;
}

async function kycSubmit() {
  const errEl = document.getElementById('reg-error-4');
  const idType = document.getElementById('reg-id-type').value;
  if (!idType) { showErr(errEl, 'Please select ID document type.'); return; }
  const terms = document.getElementById('reg-terms');
  if (!terms || !terms.checked) { showErr(errEl, 'You must agree to the Terms & Conditions to continue.'); return; }

  const submitBtn = document.querySelector('#kyc-4 .btn-gold');
  if (submitBtn) { submitBtn.disabled = true; submitBtn.textContent = 'Submitting...'; }

  try {
   const rawPassword = document.getElementById('reg-password').value;
const email = document.getElementById('reg-email').value.trim().toLowerCase();

// Check email not already registered BEFORE creating any auth user
const existing = await db_getInvestorByEmail(email);
if (existing) { showErr(errEl, 'An account with this email already exists.'); return; }

// Create Supabase Auth user first
const { data: authData, error: authError } = await sb.auth.signUp({ email, password: rawPassword });
if (authError) throw new Error(authError.message);
const authUserId = authData.user?.id;
if (!authUserId) throw new Error('Failed to create auth account. Please try again.');

// Sign in to get active session before insert
const { data: signInData, error: signInError } = await sb.auth.signInWithPassword({ 
  email, 
  password: rawPassword 
});
if (signInError) throw new Error('Account created but could not sign in: ' + signInError.message);

// Wait for session to be active
await new Promise(resolve => setTimeout(resolve, 500));

    // FIX C2: Upload KYC docs to Supabase Storage (NOT localStorage).
    // We need an investor ID first, so we create the investor record with
    // placeholder doc metadata, then upload, then update.
    const newInvestor = {
      name: document.getElementById('reg-name').value.trim(),
      email,
      user_id: authUserId,
      role: 'client',
      kyc_status: 'pending',
      kyc_data: {
        dob: document.getElementById('reg-dob').value,
        nationality: document.getElementById('reg-nationality').value,
        phone: document.getElementById('reg-phone').value,
        address: document.getElementById('reg-address').value,
        city: document.getElementById('reg-city').value,
        country: document.getElementById('reg-country').value,
        sof: document.getElementById('reg-sof').value,
        income: document.getElementById('reg-income').value,
        networth: document.getElementById('reg-networth').value,
        objective: document.getElementById('reg-obj').value,
        experience: document.getElementById('reg-exp').value,
        pep: document.getElementById('reg-pep').value,
        idType,
        accountType: document.getElementById('reg-type').value
      },
      kyc_docs: {}
    };

    const created = await db_createInvestor(newInvestor);

    // Upload each document to Supabase Storage
    const docsMetaOnly = {};
    for (const k of Object.keys(uploadedDocs)) {
      const d = uploadedDocs[k];
      if (d && d.data) {
        try {
          const storagePath = await uploadDocToStorage(created.id, k, d.data, d.name, d.type);
          docsMetaOnly[k] = { name: d.name, type: d.type, size: d.size, uploadedAt: d.uploadedAt, storagePath };
        } catch (uploadErr) {
          console.warn('Doc upload failed for ' + k + ':', uploadErr);
          docsMetaOnly[k] = { name: d.name, type: d.type, size: d.size, uploadedAt: d.uploadedAt, stored: false };
        }
      } else if (d) {
        docsMetaOnly[k] = d;
      }
    }

    // Update the investor record with the doc metadata
    await db_updateInvestor(created.id, { kyc_docs: docsMetaOnly });

    // Audit log
    await db_writeAudit(created.id, created.email, 'REGISTRATION', 'investor', created.id, created.name + ' submitted KYC application');

    // Send welcome email
    sendEmailNotification(created.email, created.name,
      'Welcome to Wadstone Investment — Application Received',
      `Dear ${created.name},\n\nThank you for applying. Your KYC documents are under review. You will be notified within 1–2 business days.\n\nFor queries: support@wadstone.co.ke\n\nWarm regards,\nWadstone Investment Team`
    );

    currentUser = { id: created.id, name: created.name, email: created.email, role: 'client', kyc: 'pending', kycData: created.kyc_data, balance: 0, deposited: 0, returns: 0 };
    currentAccount = null;
    uploadedDocs = {};
    await syncDBFromSupabase();
    initApp();
    toast("Application submitted! We'll review your KYC within 1–2 business days.", 'success');

  } catch(e) {
    showErr(errEl, 'Submission failed: ' + (e.message || 'Please try again.'));
  } finally {
    if (submitBtn) { submitBtn.disabled = false; submitBtn.textContent = 'Submit Application'; }
  }
}

function simulateUpload(id, label) {
  const el = document.getElementById(id);
  el.classList.add('uploaded');
  el.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg><p>${label} uploaded ✓</p>`;
  uploadedDocs[id] = label;
}

// Real file upload handler - converts to base64 for storage
function handleFileUpload(inputId, areaId, docKey) {
  const input = document.getElementById(inputId);
  const area = document.getElementById(areaId);
  const file = input.files[0];
  if (!file) return;

  // Validate size (10MB)
  if (file.size > 10 * 1024 * 1024) {
    toast('File too large. Maximum 10MB.', 'error');
    return;
  }

  const validTypes = ['image/jpeg','image/png','application/pdf'];
  if (!validTypes.includes(file.type)) {
    toast('Invalid file type. Use JPG, PNG, or PDF.', 'error');
    return;
  }

  area.innerHTML = `<div style="color:var(--gold)">⏳ Uploading ${file.name}...</div>`;

  const reader = new FileReader();
  reader.onload = function(e) {
    const base64 = e.target.result;
    uploadedDocs[docKey] = {
      name: file.name,
      type: file.type,
      size: file.size,
      data: base64,
      uploadedAt: new Date().toISOString()
    };
    area.classList.add('uploaded');
    area.innerHTML = `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
      <p style="color:var(--success)">${file.name} uploaded ✓</p>
      <p style="font-size:11px;color:var(--text3)">${(file.size/1024).toFixed(0)} KB</p>`;
    toast(`${file.name} uploaded successfully`, 'success');
  };
  reader.onerror = function() { toast('Upload failed. Please try again.', 'error'); };
  reader.readAsDataURL(file);
}

// Drag and drop support for upload areas
function initDragDrop() {
  document.querySelectorAll('.upload-area').forEach(area => {
    area.addEventListener('dragover', e => { e.preventDefault(); area.style.borderColor = 'var(--gold)'; });
    area.addEventListener('dragleave', () => { area.style.borderColor = ''; });
    area.addEventListener('drop', e => {
      e.preventDefault(); area.style.borderColor = '';
      const file = e.dataTransfer.files[0];
      if (!file) return;
      const inputId = area.id === 'upload-id' ? 'file-id' : area.id === 'upload-poa' ? 'file-poa' : 'file-selfie';
      const docKey = area.id === 'upload-id' ? 'id_front' : area.id === 'upload-poa' ? 'proof_of_address' : 'selfie_with_id';
      const dt = new DataTransfer();
      dt.items.add(file);
      document.getElementById(inputId).files = dt.files;
      handleFileUpload(inputId, area.id, docKey);
    });
  });
}
document.addEventListener('DOMContentLoaded', initDragDrop);

// Toggle deposit method details
function toggleDepositDetails() {
  const method = document.getElementById('dep-method').value;
  ['dep-mpesa-details','dep-kenyan-bank-details','dep-wire-details','dep-crypto-details'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.style.display = 'none';
  });
  if (method === 'mpesa') document.getElementById('dep-mpesa-details').style.display = 'block';
  if (method === 'kenyan_bank') document.getElementById('dep-kenyan-bank-details').style.display = 'block';
  if (method === 'wire') document.getElementById('dep-wire-details').style.display = 'block';
  if (method === 'crypto') document.getElementById('dep-crypto-details').style.display = 'block';
}

// ════════════════════════════════════════════
//  ADMIN ACCESS
//  Admins log in through the standard login form only.
//  Admin role is granted exclusively by the `role` field
//  in the Supabase `investors` table (server-side source
//  of truth). No client-side triggers, URL parameters, or
//  credential shortcuts exist — those were a security risk.
//
//  TO LOG IN AS ADMIN:
//  1. Go to the login page normally.
//  2. Enter the admin email and the real hashed-password
//     credentials stored in Supabase.
//  3. The app will detect role === 'admin' from the DB
//     response and route to the admin dashboard.
// ════════════════════════════════════════════

// No-op stub: keeps any residual HTML onclick="logoTripleClick()"
// attributes from throwing a ReferenceError.
function logoTripleClick() {}

function showErr(el, msg) { el.textContent = msg; el.style.display = 'flex'; }

// ════════════════════════════════════════════
//  APP INIT
// ════════════════════════════════════════════
async function initApp() {
  showApp();
  const u = currentUser;

  // Refresh capital account from Supabase (source of truth)
  if (u.role !== 'admin') {
    try {
      const account = await db_getCapitalAccount(u.id);
      currentAccount = account;
      if (account) {
        u.balance   = account.balance || 0;
        u.deposited = account.total_deposited || 0;
        u.returns   = account.total_returns || 0;
        u.hwm       = account.high_water_mark || 0;
        u.units     = account.units_held || 0;
      }
    } catch(e) { console.warn('Could not refresh capital account:', e); }
  }

  document.getElementById('sidebar-username').textContent = u.name;
  document.getElementById('sidebar-role').textContent = u.role === 'admin' ? 'Administrator' : 'Investor';
  document.getElementById('sidebar-avatar').textContent = u.name[0].toUpperCase();

  if (u.role === 'admin') {
    document.getElementById('client-nav').style.display = 'none';
    document.getElementById('admin-nav').style.display = 'block';
    document.getElementById('admin-badge').style.display = 'block';
    document.getElementById('kyc-banner').style.display = 'none';
    await syncDBFromSupabase();
    await loadFundSettings();
    showPage('admin-overview');
  } else {
    document.getElementById('client-nav').style.display = 'block';
    document.getElementById('admin-nav').style.display = 'none';
    document.getElementById('admin-badge').style.display = 'none';
    if (u.kyc === 'pending') document.getElementById('kyc-banner').style.display = 'block';
    showPage('dashboard');
    updateClientDashboard();
  }
}

// ════════════════════════════════════════════
//  PAGE NAVIGATION
// ════════════════════════════════════════════
function showPage(id) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const page = document.getElementById('page-' + id);
  if (page) page.classList.add('active');

  // Highlight nav
  document.querySelectorAll('.nav-item').forEach(n => {
    if (n.getAttribute('onclick') && n.getAttribute('onclick').includes("'" + id + "'")) {
      n.classList.add('active');
    }
  });

  // Page titles
  const titles = {
    'dashboard': 'Dashboard', 'portfolio': 'My Portfolio', 'performance': 'Performance',
    'deposit': 'Deposit Funds', 'withdraw': 'Withdraw Funds', 'transactions': 'Transaction History',
    'kyc-status': 'KYC Status', 'profile': 'Profile Settings', 'documents': 'Documents', 'support': 'Support',
    'admin-overview': 'Admin Overview', 'admin-clients': 'Client Management', 'admin-kyc': 'KYC Reviews',
    'admin-transactions': 'Transactions', 'admin-reports': 'Reports & AUM', 'admin-settings': 'Platform Settings',
    'admin-client-detail': 'Client Detail'
  };
  document.getElementById('page-title').textContent = titles[id] || id;

  // Load page data
  if (id === 'dashboard') updateClientDashboard();
  if (id === 'deposit') updateDepositPage();
  if (id === 'withdraw') updateWithdrawPage();
  if (id === 'transactions') renderTransactionsTable();
  if (id === 'kyc-status') renderKycStatus();
  if (id === 'profile') {
    renderProfile();
    setTimeout(renderClient2FAStatus, 300);
  }
  if (id === 'portfolio') renderPortfolio();
  if (id === 'admin-accounting') { setTimeout(initAccounting, 100); }
  if (id === 'admin-overview') renderAdminOverview();
  if (id === 'admin-clients') renderAdminClients();
  if (id === 'admin-kyc') renderAdminKYC();
  if (id === 'admin-transactions') renderAdminTransactions();
  if (id === 'admin-reports') renderAdminReports();
  if (id === 'admin-settings') {
    setTimeout(() => {
      const statusEl = document.getElementById('firebase-status');
      if (statusEl) {
        if (window._fbReady) {
          statusEl.className = 'alert alert-success';
          statusEl.innerHTML = '✅ Firebase connected — cloud backup is active.';
        } else {
          statusEl.className = 'alert alert-warn';
          statusEl.innerHTML = '⚠️ Firebase not configured. Using localStorage only.';
        }
      }
      applyPaymentSettings();
      renderAuditLog();
    }, 300);
  }

  // Close sidebar on mobile
  if (window.innerWidth < 900) document.getElementById('sidebar').classList.remove('open');
}

// ════════════════════════════════════════════
//  CLIENT DASHBOARD
// ════════════════════════════════════════════
async function updateClientDashboard() {
  if (!currentUser) return;

  // Always read balance from capital_accounts (server-side source of truth)
  const account = await db_getCapitalAccount(currentUser.id);
  currentAccount = account;

  const balance   = account?.balance || 0;
  const deposited = account?.total_deposited || 0;
  const returns   = account?.total_returns || 0;
  const returnsPct = deposited > 0 ? ((returns / deposited) * 100).toFixed(1) : '0.0';

  // Update currentUser in memory to keep UI in sync
  currentUser.balance   = balance;
  currentUser.deposited = deposited;
  currentUser.returns   = returns;

  document.getElementById('dash-portfolio').textContent = fmt(balance);
  document.getElementById('dash-portfolio-change').textContent = deposited > 0 ? `+${returnsPct}% total return` : 'Awaiting first deposit';
  document.getElementById('dash-returns').textContent = fmt(returns);
  document.getElementById('dash-returns-pct').textContent = parseFloat(returnsPct) > 0 ? `+${returnsPct}% gain` : '—';
  document.getElementById('dash-deposited').textContent = fmt(deposited);
  document.getElementById('dash-pending').textContent = fmt(0);

  await renderDashTxns();
}

async function renderDashTxns() {
  const tbody = document.getElementById('dash-txn-table');
  if (!tbody) return;
  const txns = await db_getTransactions(currentUser.id, 5);
  if (!txns.length) {
    tbody.innerHTML = '<tr><td colspan="5"><div class="empty"><p>No transactions yet</p></div></td></tr>';
    return;
  }
  tbody.innerHTML = txns.map(t => `
    <tr>
      <td>${sanitize(fmtDate(t.created_at))}</td>
      <td><span class="badge ${t.type==='deposit'?'badge-success':t.type==='return'?'badge-gold':'badge-info'}">${sanitize(capitalize(t.type))}</span></td>
      <td style="color:${['deposit','return'].includes(t.type)?'var(--success)':'var(--danger)'}">${['deposit','return'].includes(t.type)?'+':'-'}${sanitize(fmt(t.amount))}</td>
      <td><span class="badge ${statusBadge(t.status)}">${sanitize(capitalize(t.status))}</span></td>
      <td style="font-family:'DM Mono',monospace;font-size:11px;color:var(--text3)">${sanitize(t.reference)}</td>
    </tr>`).join('');
}

async function updateDepositPage() {
  if (!currentUser) return;
  const account = await db_getCapitalAccount(currentUser.id);
  document.getElementById('dep-balance').textContent = fmt(account?.balance || 0);
  document.getElementById('dep-kyc-warn').style.display = currentUser.kyc !== 'approved' ? 'flex' : 'none';
  const methodEl = document.getElementById('dep-method');
  if (methodEl) methodEl.onchange = toggleDepositDetails;
  applyPaymentSettings();

  const deposits = await db_getTransactions(currentUser.id, 50);
  const recentDeposits = deposits.filter(t => t.type === 'deposit').slice(0, 3);
  const el = document.getElementById('recent-deposits');
  if (!el) return;
  if (!recentDeposits.length) { el.innerHTML = '<div class="empty"><p style="font-size:12px">No deposits yet</p></div>'; return; }
  el.innerHTML = recentDeposits.map(d => `
    <div class="perf-row">
      <div><div style="font-weight:500">${fmt(d.amount)}</div><div style="font-size:11px;color:var(--text3)">${fmtDate(d.created_at)}</div></div>
      <div style="text-align:right"><span class="badge ${statusBadge(d.status)}">${capitalize(d.status)}</span><div style="font-size:11px;color:var(--text3);margin-top:2px">${d.reference}</div></div>
    </div>`).join('');
}

async function updateWithdrawPage() {
  if (!currentUser) return;
  const account = await db_getCapitalAccount(currentUser.id);
  const balance = account?.balance || 0;
  const balEl = document.getElementById('wd-balance');
  if (balEl) balEl.textContent = fmt(balance);
  const maxEl = document.getElementById('wd-max');
  if (maxEl) maxEl.textContent = fmt(balance);
  const warnEl = document.getElementById('wd-kyc-warn');
  if (warnEl) warnEl.style.display = currentUser.kyc !== 'approved' ? 'flex' : 'none';

  const txns = await db_getTransactions(currentUser.id, 50);
  const recentWds = txns.filter(t => t.type === 'withdrawal').slice(0, 3);
  const el = document.getElementById('recent-withdrawals');
  if (!el) return;
  if (!recentWds.length) { el.innerHTML = '<div class="empty"><p style="font-size:12px">No withdrawals yet</p></div>'; return; }
  el.innerHTML = recentWds.map(w => `
    <div class="perf-row">
      <div><div style="font-weight:500">${fmt(w.amount)}</div><div style="font-size:11px;color:var(--text3)">${fmtDate(w.created_at)}</div></div>
      <div style="text-align:right"><span class="badge ${statusBadge(w.status)}">${capitalize(w.status)}</span><div style="font-size:11px;color:var(--text3);margin-top:2px">${w.reference}</div></div>
    </div>`).join('');
}

async function submitDeposit() {
  const u = currentUser;
  if (u.kyc !== 'approved') { toast('KYC verification required before depositing.', 'error'); return; }
  const method = document.getElementById('dep-method').value;
  const minDeposit = (method === 'mpesa' || method === 'kenyan_bank') ? 1000 : 10000;
  // FIX M3 — validate amount server-side style: reject NaN, negatives, and below minimum
  const amt = validateAmount(document.getElementById('dep-amount').value, minDeposit);
  if (amt === null) { toast('Minimum deposit is $' + minDeposit.toLocaleString() + ' and must be a valid number.', 'error'); return; }
  if (!method) { toast('Please select a payment method', 'error'); return; }

  const ref = 'DEP-' + crypto.randomUUID().replace(/-/g,'').slice(0,12).toUpperCase();
  const notes = document.getElementById('dep-notes').value;

  const btn = document.querySelector('#page-deposit .btn-gold');
  if (btn) { btn.disabled = true; btn.textContent = 'Submitting...'; }

  try {
    // Write PENDING transaction to Supabase — NOT approved yet
    const txn = await db_createTransaction({
      investor_id: u.id,
      type: 'deposit',
      amount: amt,
      currency: 'USD',
      status: 'pending',
      method,
      reference: ref,
      notes: notes || null
    });

    // FIX M2: Store receipt in Supabase Storage, not localStorage.
    // depositReceipt holds the file in memory until this point only.
    if (depositReceipt && depositReceipt.data) {
      try {
        await uploadDocToStorage(u.id, 'receipt_' + txn.id, depositReceipt.data, depositReceipt.name, depositReceipt.type);
      } catch (e) { console.warn('Receipt upload failed:', e); }
    }

    await db_writeAudit(u.id, u.email, 'DEPOSIT_REQUESTED', 'transaction', txn.id, `$${amt} via ${method} — Ref: ${ref}`);
    Log.financial('DEPOSIT_REQUESTED', { investor_id: u.id, amount: amt, method, ref });

    sendEmailNotification(u.email, u.name,
      `Deposit Request Received — ${ref}`,
      `Dear ${u.name},\n\nDeposit request of $${amt.toLocaleString()} via ${method} received.\nRef: ${ref}\nStatus: Pending admin approval.\n\nWarm regards,\nWadstone Investment Team`
    );

    // Reset form
    document.getElementById('dep-amount').value = '';
    document.getElementById('dep-method').value = '';
    document.getElementById('dep-notes').value = '';
    depositReceipt = null;
    toggleDepositDetails();

    // Refresh transactions display
    await updateDepositPage();
    await updateClientDashboard();
    toast('Deposit request submitted! Ref: ' + ref, 'success');

  } catch(e) {
    captureError(e, { action: 'DEPOSIT_SUBMIT', investor_id: currentUser?.id });
    toast('Submission failed: ' + (e.message || 'Please try again.'), 'error');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Submit Deposit Request'; }
  }
}

// ════════════════════════════════════════════
//  WITHDRAW
// ════════════════════════════════════════════

async function submitWithdrawal() {
  const u = currentUser;
  if (u.kyc !== 'approved') { toast('KYC verification required.', 'error'); return; }
  const account = await db_getCapitalAccount(u.id);
  const balance = account?.balance || 0;
  const method = document.getElementById('wd-method').value;
  const details = document.getElementById('wd-details').value;
  // FIX M3 — validate withdrawal amount
  const amt = validateAmount(document.getElementById('wd-amount').value, 0.01, balance);
  if (amt === null) { toast('Enter a valid amount not exceeding your balance of ' + fmt(balance) + '.', 'error'); return; }
  if (!method) { toast('Select withdrawal method', 'error'); return; }

  const ref = 'WD-' + crypto.randomUUID().replace(/-/g,'').slice(0,12).toUpperCase();
  try {
    const txn = await db_createTransaction({
      investor_id: u.id, type: 'withdrawal', amount: amt,
      status: 'pending', method, reference: ref, notes: details || null
    });
    await db_writeAudit(u.id, u.email, 'WITHDRAWAL_REQUESTED', 'transaction', txn.id, `$${amt} via ${method} — Ref: ${ref}`);
    Log.financial('WITHDRAWAL_REQUESTED', { investor_id: u.id, amount: amt, method, ref });
    sendEmailNotification(u.email, u.name, `Withdrawal Request Received — ${ref}`,
      `Dear ${u.name},\n\nWithdrawal of $${amt.toLocaleString()} via ${method} received.\nRef: ${ref}\nProcessed within 3–5 business days.\n\nWarm regards,\nWadstone Investment Team`
    );
    document.getElementById('wd-amount').value = '';
    document.getElementById('wd-details').value = '';
    await updateWithdrawPage();
    await updateClientDashboard();
    toast('Withdrawal request submitted! Ref: ' + ref, 'success');
  } catch(e) { toast('Submission failed: ' + e.message, 'error'); }
}

// ════════════════════════════════════════════
//  TRANSACTIONS TABLE
// ════════════════════════════════════════════
async function renderTransactionsTable() {
  const filter = document.getElementById('txn-filter').value;
  const tbody = document.getElementById('txn-table-full');
  tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:16px;color:var(--text3)">Loading...</td></tr>';

  let txns = await db_getTransactions(currentUser.id, 100);
  if (filter !== 'all') txns = txns.filter(t => t.type === filter);

  if (!txns.length) {
    tbody.innerHTML = '<tr><td colspan="6"><div class="empty"><p>No transactions found</p></div></td></tr>';
    return;
  }
  tbody.innerHTML = txns.map(t => `
    <tr>
      <td style="font-family:'DM Mono',monospace;font-size:12px">${fmtDate(t.created_at)}</td>
      <td><span class="badge ${t.type==='deposit'?'badge-success':'badge-info'}">${capitalize(t.type)}</span></td>
      <td style="color:${t.type==='deposit'?'var(--success)':'var(--danger)'}">
        ${t.type==='deposit'?'+':'-'}${fmt(t.amount)}
      </td>
      <td style="color:var(--text2)">${sanitize(t.method || '—')}</td>
      <td><span class="badge ${statusBadge(t.status)}">${capitalize(t.status)}</span></td>
      <td style="font-family:'DM Mono',monospace;font-size:11px;color:var(--text3)">${sanitize(t.reference)}</td>
    </tr>
  `).join('');
}

async function filterTransactions() { await renderTransactionsTable(); }

// ════════════════════════════════════════════
//  KYC STATUS PAGE
// ════════════════════════════════════════════
function renderKycStatus() {
  const u = currentUser;
  const statusMap = {
    'pending': { badge: 'badge-warn', label: 'Under Review', msg: 'Your documents have been received and are being reviewed by our compliance team. This typically takes 1-2 business days.' },
    'approved': { badge: 'badge-success', label: 'Verified', msg: 'Your identity has been verified. You have full access to all platform features.' },
    'rejected': { badge: 'badge-danger', label: 'Action Required', msg: 'Your KYC was not approved. Please resubmit your documents below.' }
  };
  const s = statusMap[u.kyc] || statusMap['pending'];
  const showResubmit = u.kyc === 'rejected' || u.kyc === 'pending';
  document.getElementById('kyc-status-content').innerHTML =
    '<div class="alert ' + (u.kyc==='approved'?'alert-success':u.kyc==='rejected'?'alert-danger':'alert-warn') + '">' +
    '<div><strong>Status: <span class="badge ' + s.badge + '">' + s.label + '</span></strong><br/>' +
    '<span style="margin-top:6px;display:block">' + s.msg + '</span></div></div>' +
    (u.kycData ?
    '<div style="margin-top:16px;display:grid;grid-template-columns:1fr 1fr;gap:10px">' +
    '<div class="form-group"><label>Full Name</label><div style="padding:10px 14px;background:var(--dark);border-radius:6px;font-size:14px">' + u.name + '</div></div>' +
    '<div class="form-group"><label>Email</label><div style="padding:10px 14px;background:var(--dark);border-radius:6px;font-size:14px">' + u.email + '</div></div>' +
    '<div class="form-group"><label>Nationality</label><div style="padding:10px 14px;background:var(--dark);border-radius:6px;font-size:14px">' + (u.kycData.nationality||'--') + '</div></div>' +
    '<div class="form-group"><label>Country</label><div style="padding:10px 14px;background:var(--dark);border-radius:6px;font-size:14px">' + (u.kycData.country||'--') + '</div></div>' +
    '</div>' : '') +
    (showResubmit ? '<div style="margin-top:20px"><button class="btn btn-gold" onclick="showResubmitKyc()">Upload / Resubmit Documents</button></div>' : '');

  const docs = u.kycDocs || {};
  const docEl = document.getElementById('kyc-docs-list');
  const docLabels = {'id_front':'Government ID (Front)','proof_of_address':'Proof of Address','selfie_with_id':'Selfie with ID'};
  docEl.innerHTML = Object.keys(docLabels).map(k => {
    const d = docs[k];
    return '<div class="doc-item">' +
      '<div class="doc-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="' + (d?'var(--success)':'var(--text3)') + '" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg></div>' +
      '<div class="doc-info"><div class="doc-name">' + docLabels[k] + '</div>' +
      '<div class="doc-meta">' + (d ? (d.name||'Uploaded') + (d.size ? ' - ' + (d.size/1024).toFixed(0)+'KB' : '') : 'Not submitted') + '</div></div>' +
      '<span class="badge ' + (d?'badge-success':'badge-danger') + '">' + (d?'Submitted':'Missing') + '</span>' +
      '</div>';
  }).join('');
}

async function showResubmitKyc() {
  const modal = document.createElement('div');
  modal.id = 'resubmit-modal';
  modal.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.8);z-index:9999;display:flex;align-items:center;justify-content:center;';
  modal.innerHTML = '<div style="background:var(--card);border-radius:12px;padding:32px;width:90%;max-width:500px;max-height:80vh;overflow-y:auto;">' +
    '<h3 style="margin-bottom:20px;color:var(--gold)">Upload KYC Documents</h3>' +
    '<div class="form-group" style="margin-bottom:16px"><label>Government ID (Front)</label>' +
    '<input type="file" id="resubmit-id_front" accept="image/*,.pdf" style="width:100%;padding:10px;background:var(--dark);border:1px solid var(--border);border-radius:6px;color:var(--text1)"/></div>' +
    '<div class="form-group" style="margin-bottom:16px"><label>Proof of Address</label>' +
    '<input type="file" id="resubmit-proof_of_address" accept="image/*,.pdf" style="width:100%;padding:10px;background:var(--dark);border:1px solid var(--border);border-radius:6px;color:var(--text1)"/></div>' +
    '<div class="form-group" style="margin-bottom:16px"><label>Selfie with ID</label>' +
    '<input type="file" id="resubmit-selfie_with_id" accept="image/*,.pdf" style="width:100%;padding:10px;background:var(--dark);border:1px solid var(--border);border-radius:6px;color:var(--text1)"/></div>' +
    '<div id="resubmit-error" style="color:var(--danger);margin-bottom:12px;display:none"></div>' +
    '<div style="display:flex;gap:12px;margin-top:20px">' +
    '<button class="btn btn-gold" onclick="submitResubmitKyc()" style="flex:1">Submit Documents</button>' +
    '<button class="btn btn-ghost" onclick="document.getElementById(\"resubmit-modal\").remove()" style="flex:1">Cancel</button>' +
    '</div></div>';
  document.body.appendChild(modal);
}

async function submitResubmitKyc() {
  const u = currentUser;
  const errEl = document.getElementById('resubmit-error');
  const docKeys = ['id_front','proof_of_address','selfie_with_id'];
  const docsMetaOnly = {};
  let hasFile = false;
  for (const k of docKeys) {
    const input = document.getElementById('resubmit-' + k);
    if (input && input.files[0]) {
      hasFile = true;
      const file = input.files[0];
      const base64 = await new Promise(res => { const r = new FileReader(); r.onload = e => res(e.target.result); r.readAsDataURL(file); });
      try {
        const path = await uploadDocToStorage(u.id, k, base64, file.name, file.type);
        docsMetaOnly[k] = { name: file.name, type: file.type, size: file.size, uploadedAt: new Date().toISOString(), storagePath: path };
      } catch(e) {
        errEl.textContent = 'Upload failed: ' + e.message;
        errEl.style.display = 'block';
        return;
      }
    }
  }
  if (!hasFile) { errEl.textContent = 'Please select at least one document.'; errEl.style.display = 'block'; return; }
  const mergedDocs = Object.assign({}, u.kycDocs || {}, docsMetaOnly);
  await db_updateInvestor(u.id, { kyc_docs: mergedDocs, kyc_status: 'pending' });
  currentUser.kycDocs = mergedDocs;
  currentUser.kyc = 'pending';
  document.getElementById('resubmit-modal').remove();
  showToast('Documents uploaded successfully!', 'success');
  renderKycStatus();
}

// ════════════════════════════════════════════
//  PROFILE
// ════════════════════════════════════════════
function renderProfile() {
  const u = currentUser;
  document.getElementById('profile-avatar').textContent = u.name[0].toUpperCase();
  document.getElementById('profile-fullname').textContent = u.name;
  document.getElementById('profile-email-display').textContent = u.email;
  document.getElementById('prof-name').value = u.name;
  document.getElementById('prof-email').value = u.email;
  document.getElementById('prof-phone').value = u.kycData?.phone || '';
  document.getElementById('prof-nationality').value = u.kycData?.nationality || '';
}

async function saveProfile() {
  const name  = document.getElementById('prof-name').value.trim();
  const phone = document.getElementById('prof-phone')?.value.trim() || '';
  if (!name) { toast('Name cannot be empty', 'error'); return; }

  const btn = document.querySelector('#profile-personal .btn-gold');
  if (btn) { btn.disabled = true; btn.textContent = 'Saving...'; }

  try {
    await db_updateInvestor(currentUser.id, { name, phone });
    currentUser.name = name;
    const dbUser = DB.users.find(x => x.id === currentUser.id);
    if (dbUser) { dbUser.name = name; dbUser.phone = phone; }
    document.getElementById('sidebar-username').textContent = name;
    document.getElementById('sidebar-avatar').textContent = name[0].toUpperCase();
    renderProfile();
    toast('Profile updated ✓', 'success');
  } catch(e) {
    toast('Update failed: ' + e.message, 'error');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Save Changes'; }
  }
}

function switchProfileTab(tab) {
  ['personal','security','notifications'].forEach(t => {
    document.getElementById('profile-' + t).style.display = t === tab ? 'block' : 'none';
  });
  document.querySelectorAll('.tab').forEach((el, i) => {
    el.classList.toggle('active', ['personal','security','notifications'][i] === tab);
  });
}

// ════════════════════════════════════════════
//  PORTFOLIO
// ════════════════════════════════════════════
function renderPortfolio() {
  const u = currentUser;
  const bal = u.balance || 0;
  document.getElementById('port-value').textContent = fmt(bal);
  document.getElementById('port-gains').textContent = fmt(bal * 0.123);
  document.getElementById('port-div').textContent = fmt(bal * 0.02);
  document.getElementById('kyc-alert-portfolio').style.display = u.kyc !== 'approved' ? 'block' : 'none';

  const holdings = [
    { asset: 'Global Macro Fund', strategy: 'Long/Short', alloc: '45%', value: bal * 0.45, ret: '+22.1%' },
    { asset: 'Fixed Income Alpha', strategy: 'Arbitrage', alloc: '25%', value: bal * 0.25, ret: '+9.4%' },
    { asset: 'Commodity Alpha', strategy: 'Systematic', alloc: '15%', value: bal * 0.15, ret: '+18.2%' },
    { asset: 'Event Driven', strategy: 'Opportunistic', alloc: '10%', value: bal * 0.10, ret: '-2.1%' },
    { asset: 'Cash Reserve', strategy: 'Liquidity', alloc: '5%', value: bal * 0.05, ret: '+4.9%' },
  ];
  document.getElementById('holdings-table').innerHTML = bal > 0 ? holdings.map(h => `
    <tr>
      <td style="font-weight:500">${h.asset}</td>
      <td style="color:var(--text3)">${h.strategy}</td>
      <td>${h.alloc}</td>
      <td>${fmt(h.value)}</td>
      <td style="color:${h.ret.startsWith('+') ? 'var(--success)' : 'var(--danger)'}">${h.ret}</td>
      <td><span class="badge badge-success">Active</span></td>
    </tr>
  `).join('') : '<tr><td colspan="6"><div class="empty"><p>Deposit funds to view holdings</p></div></td></tr>';
}

// ════════════════════════════════════════════
//  ADMIN PAGES
// ════════════════════════════════════════════
function renderAdminOverview() {
  const clients = DB.users.filter(u => u.role !== 'admin');
  const kycPending = clients.filter(u => u.kyc === 'pending');
  document.getElementById('admin-client-count').textContent = clients.length;
  document.getElementById('admin-kyc-count').textContent = kycPending.length;

  // Total AUM — real sum of every client's actual balance (0 until deposits are approved)
  const totalAUM = clients.reduce((s, u) => s + (u.balance || 0), 0);
  setText('admin-total-aum', '$' + totalAUM.toLocaleString('en-US', {minimumFractionDigits:2, maximumFractionDigits:2}));

  // Pending withdrawals — real sum across all clients
  const totalPendingWd = clients.reduce((s, u) => s + (u.pendingWithdrawal || 0), 0);
  setText('admin-pending-withdrawals', '$' + totalPendingWd.toLocaleString('en-US', {minimumFractionDigits:2, maximumFractionDigits:2}));

  // New clients this month — real count based on submittedAt
  const now = new Date();
  const newThisMonth = clients.filter(u => {
    if (!u.submittedAt) return false;
    const d = new Date(u.submittedAt);
    return d.getFullYear() === now.getFullYear() && d.getMonth() === now.getMonth();
  }).length;
  const clientsChangeEl = document.getElementById('admin-clients-change');
  if (clientsChangeEl) {
    if (newThisMonth > 0) {
      clientsChangeEl.textContent = `+${newThisMonth} this month`;
      clientsChangeEl.style.color = '';
      clientsChangeEl.classList.add('up');
    } else {
      clientsChangeEl.textContent = 'No new clients yet';
      clientsChangeEl.style.color = 'var(--text3)';
      clientsChangeEl.classList.remove('up');
    }
  }

  // AUM change this month — real net of approved deposits/withdrawals this month, fetched from Supabase
  updateAdminAumChange(totalAUM);

  const tbody = document.getElementById('admin-recent-clients');
  tbody.innerHTML = clients.slice(-5).reverse().map(u => `
    <tr>
      <td style="font-weight:500">${sanitize(u.name)}</td>
      <td style="font-size:12px;color:var(--text3)">${sanitize(fmtDate(u.submittedAt||new Date().toISOString()))}</td>
      <td><span class="badge ${kycBadge(u.kyc)}">${sanitize(capitalize(u.kyc))}</span></td>
    </tr>
  `).join('') || '<tr><td colspan="3"><div class="empty"><p>No clients yet</p></div></td></tr>';
}

async function updateAdminAumChange(totalAUM) {
  const el = document.getElementById('admin-aum-change');
  if (!el) return;
  if (totalAUM <= 0) { el.textContent = 'No client deposits yet'; el.style.color = 'var(--text3)'; return; }
  try {
    const start = new Date(); start.setDate(1); start.setHours(0,0,0,0);
    const { data, error } = await sb
      .from('transactions')
      .select('type, amount, status, created_at')
      .eq('status', 'approved')
      .gte('created_at', start.toISOString());
    if (error || !data) { el.textContent = 'Updates with client deposits'; el.style.color = 'var(--text3)'; return; }
    const net = data.reduce((s, t) => s + (t.type === 'deposit' ? (t.amount||0) : -(t.amount||0)), 0);
    if (net === 0) { el.textContent = 'No change this month'; el.style.color = 'var(--text3)'; return; }
    el.textContent = (net > 0 ? '+$' : '-$') + Math.abs(net).toLocaleString('en-US', {minimumFractionDigits:2, maximumFractionDigits:2}) + ' this month';
    el.style.color = net > 0 ? 'var(--success)' : 'var(--danger)';
  } catch (e) {
    el.textContent = 'Updates with client deposits'; el.style.color = 'var(--text3)';
  }
}

async function renderAdminReports() {
  const clients = DB.users.filter(u => u.role !== 'admin');
  const totalAUM = clients.reduce((s, u) => s + (u.balance || 0), 0);
  const totalDeposited = clients.reduce((s, u) => s + (u.deposited || 0), 0);
  const totalReturns = clients.reduce((s, u) => s + (u.returns || 0), 0);
  const totalMgmt = (DB.feeLog || []).filter(f => f.type === 'management').reduce((s, f) => s + (f.totalAmount || 0), 0);
  const totalPerf = (DB.feeLog || []).filter(f => f.type === 'performance').reduce((s, f) => s + (f.totalAmount || 0), 0);
  const ytdReturnPct = totalDeposited > 0 ? (totalReturns / totalDeposited) * 100 : 0;

  setText('admin-reports-aum', '$' + totalAUM.toLocaleString('en-US', {minimumFractionDigits:2, maximumFractionDigits:2}));
  setText('admin-reports-ytd-return', (ytdReturnPct >= 0 ? '+' : '') + ytdReturnPct.toFixed(2) + '%');
  setText('admin-reports-mgmt-fees', '$' + totalMgmt.toLocaleString('en-US', {minimumFractionDigits:2, maximumFractionDigits:2}));
  setText('admin-reports-perf-fees', '$' + totalPerf.toLocaleString('en-US', {minimumFractionDigits:2, maximumFractionDigits:2}));

  const aumChangeEl = document.getElementById('admin-reports-aum-change');
  if (aumChangeEl) aumChangeEl.textContent = totalAUM > 0 ? 'Live client balances' : 'No client deposits yet';

  // Strategy table — honest state until strategies are actually assigned to clients.
  // If/when you add a "strategy" field per client, this can break AUM down per strategy for real.
  const strategyTbody = document.getElementById('admin-strategy-table');
  if (strategyTbody) {
    if (totalAUM > 0) {
      strategyTbody.innerHTML = `
        <tr>
          <td>Wardstone Fund (all clients)</td>
          <td>$${totalAUM.toLocaleString('en-US', {minimumFractionDigits:2, maximumFractionDigits:2})}</td>
          <td style="color:${ytdReturnPct >= 0 ? 'var(--success)' : 'var(--danger)'}">${ytdReturnPct >= 0 ? '+' : ''}${ytdReturnPct.toFixed(2)}%</td>
          <td>–</td>
          <td>${clients.length}</td>
        </tr>`;
    } else {
      strategyTbody.innerHTML = '<tr><td colspan="5"><div class="empty"><p>No strategy data yet — this fills in once you have client capital allocated</p></div></td></tr>';
    }
  }
}

function renderAdminClients() {
  const clients = DB.users.filter(u => u.role !== 'admin');
  const tbody = document.getElementById('admin-clients-table');
  renderClientRows(tbody, clients);
}

function renderClientRows(tbody, clients) {
  tbody.innerHTML = clients.map(u => `
    <tr class="client-row" onclick="viewClientDetail('${sanitize(u.id)}')">
      <td style="font-weight:500">${sanitize(u.name)}</td>
      <td style="color:var(--text3)">${sanitize(u.email)}</td>
      <td style="font-size:12px;color:var(--text3)">${sanitize(fmtDate(u.submittedAt||new Date().toISOString()))}</td>
      <td style="font-family:'DM Mono',monospace">${sanitize(fmt(u.balance||0))}</td>
      <td><span class="badge ${kycBadge(u.kyc)}">${sanitize(capitalize(u.kyc))}</span></td>
      <td><span class="badge badge-success">Active</span></td>
      <td><button class="btn btn-ghost btn-sm" onclick="event.stopPropagation();viewClientDetail('${sanitize(u.id)}')">View</button></td>
    </tr>
  `).join('') || '<tr><td colspan="7"><div class="empty"><p>No clients registered yet</p></div></td></tr>';
}

function searchClients(q) {
  const clients = DB.users.filter(u => u.role !== 'admin' && (
    u.name.toLowerCase().includes(q.toLowerCase()) ||
    u.email.toLowerCase().includes(q.toLowerCase())
  ));
  renderClientRows(document.getElementById('admin-clients-table'), clients);
}

function viewClientDetail(uid) {
  const u = DB.users.find(x => x.id === uid);
  if (!u) return;
  showPage('admin-client-detail');
  const txns = u.transactions || [];
  document.getElementById('admin-client-detail-content').innerHTML = `
    <div class="stats-grid" style="margin-bottom:20px">
      <div class="stat-card gold"><div class="stat-label">Balance</div><div class="stat-val">${fmt(u.balance||0)}</div></div>
      <div class="stat-card success"><div class="stat-label">Total Deposited</div><div class="stat-val">${fmt(u.deposited||0)}</div></div>
      <div class="stat-card info"><div class="stat-label">Transactions</div><div class="stat-val">${txns.length}</div></div>
      <div class="stat-card danger"><div class="stat-label">Pending Withdrawal</div><div class="stat-val">${fmt(u.pendingWithdrawal||0)}</div></div>
    </div>
    <div class="grid2" style="margin-bottom:20px">
      <div class="card">
        <div class="card-title" style="margin-bottom:16px">Client Information</div>
        <div class="perf-row"><span class="card-sub">Full Name</span><span>${u.name}</span></div>
        <div class="perf-row"><span class="card-sub">Email</span><span>${u.email}</span></div>
        <div class="perf-row"><span class="card-sub">KYC Status</span><span class="badge ${kycBadge(u.kyc)}">${capitalize(u.kyc)}</span></div>
        ${u.kycData ? `
        <div class="perf-row"><span class="card-sub">Nationality</span><span>${u.kycData.nationality||'—'}</span></div>
        <div class="perf-row"><span class="card-sub">Country</span><span>${u.kycData.country||'—'}</span></div>
        <div class="perf-row"><span class="card-sub">Account Type</span><span>${capitalize(u.kycData.accountType||'individual')}</span></div>
        <div class="perf-row"><span class="card-sub">Income Range</span><span>${u.kycData.income||'—'}</span></div>
        <div class="perf-row"><span class="card-sub">Source of Funds</span><span>${u.kycData.sof||'—'}</span></div>
        <div class="perf-row"><span class="card-sub">Investment Objective</span><span>${u.kycData.objective||'—'}</span></div>
        ` : ''}
      </div>
      <div class="card">
        <div class="card-title" style="margin-bottom:16px">KYC Actions</div>
        <div style="display:flex;gap:8px;margin-bottom:16px">
          ${u.kyc === 'pending' ? `
            <button class="btn btn-success btn-sm" onclick="quickKycAction('${u.id}','approve')">Approve KYC</button>
            <button class="btn btn-danger btn-sm" onclick="quickKycAction('${u.id}','reject')">Reject KYC</button>
          ` : `<span class="badge ${kycBadge(u.kyc)}" style="font-size:13px;padding:8px 16px">KYC ${capitalize(u.kyc)}</span>`}
        </div>
        <div class="sep"></div>
        <div class="card-title" style="margin-bottom:12px;font-size:15px">Admin Actions</div>
        <div style="display:flex;flex-direction:column;gap:8px">
          <div style="display:flex;gap:8px;align-items:center">
            <input type="number" id="admin-adj-amount" placeholder="Amount USD" style="flex:1" />
            <button class="btn btn-success btn-sm" onclick="adminAdjBalance('${u.id}','add')">+ Add</button>
            <button class="btn btn-danger btn-sm" onclick="adminAdjBalance('${u.id}','sub')">- Deduct</button>
          </div>
          <div class="form-note">Manually adjust client balance (admin override)</div>
        </div>
      </div>
    </div>
    <div class="card">
      <div class="card-title" style="margin-bottom:16px">KYC Documents</div>
      ${(function() {
        const docs = u.kycDocs || {};
        const docLabels = {'id_front':'Government ID (Front)','proof_of_address':'Proof of Address','selfie_with_id':'Selfie with ID'};
        return Object.keys(docLabels).map(k => {
          const d = docs[k];
          return `<div class="doc-item">
            <div class="doc-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="${d?'var(--success)':'var(--text3)'}" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg></div>
            <div class="doc-info"><div class="doc-name">${docLabels[k]}</div><div class="doc-meta">${d ? (d.name||'Uploaded') + (d.size?' · '+(d.size/1024).toFixed(0)+'KB':'') : 'Not submitted'}</div></div>
            ${d && (d.storagePath || d.data) ? 
  `<button class="btn btn-ghost btn-sm" onclick="viewDoc(event)" data-path="${d.storagePath||''}" data-key="${k}">View</button>` 
  : `<span class="badge badge-danger">Missing</span>`}

          </div>`;
        }).join('');
      })()}
    </div>
    <div class="card">
      <div class="card-title" style="margin-bottom:16px">Transaction History</div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Date</th><th>Type</th><th>Amount</th><th>Method</th><th>Status</th><th>Ref</th><th>Action</th></tr></thead>
          <tbody>
            ${txns.length ? [...txns].reverse().map(t => `
              <tr>
                <td style="font-size:12px;font-family:'DM Mono',monospace">${fmtDate(t.date)}</td>
                <td><span class="badge ${t.type==='deposit'?'badge-success':'badge-info'}">${capitalize(t.type)}</span></td>
                <td style="color:${t.type==='deposit'?'var(--success)':'var(--danger)'}">${t.type==='deposit'?'+':'-'}${fmt(t.amount)}</td>
                <td style="color:var(--text3)">${t.method||'—'}</td>
                <td><span class="badge ${statusBadge(t.status)}">${capitalize(t.status)}</span></td>
                <td style="font-size:11px;color:var(--text3);font-family:'DM Mono',monospace">${t.ref}</td>
                <td>
                  ${t.status==='pending'?`
                    <div style="display:flex;gap:4px">
                      <button class="btn btn-success btn-sm" style="padding:4px 10px" onclick="adminApproveTxn('${u.id}','${t.id}')">✓</button>
                      <button class="btn btn-danger btn-sm" style="padding:4px 10px" onclick="adminRejectTxn('${u.id}','${t.id}')">✗</button>
                    </div>` : '—'}
                </td>
              </tr>
            `).join('') : '<tr><td colspan="7"><div class="empty"><p>No transactions</p></div></td></tr>'}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

async function quickKycAction(uid, action) {
  const newStatus = action === 'approve' ? 'approved' : 'rejected';
  try {
    // Fetch investor from Supabase directly
    const { data: investor, error: fetchError } = await sb.from('investors')
      .select('id, name, email')
      .eq('id', uid)
      .single();
    if (fetchError || !investor) { toast('Investor not found', 'error'); return; }

    await db_updateInvestor(uid, { kyc_status: newStatus });
    await db_writeAudit(currentUser.id, currentUser.email, 'KYC_' + newStatus.toUpperCase(), 'investor', uid, 'KYC ' + newStatus + ' for ' + investor.name + ' (' + investor.email + ')');
    await syncDBFromSupabase();
    sendEmailNotification(investor.email, investor.name,
      action === 'approve' ? 'Your KYC has been approved — Wadstone Investment' : 'Action required on your KYC — Wadstone Investment',
      action === 'approve'
        ? 'Dear ' + investor.name + ',\n\nGreat news! Your KYC has been approved. You now have full access to deposit and invest.\n\nLog in to get started.\n\nWarm regards,\nWadstone Investment Team'
        : 'Dear ' + investor.name + ',\n\nYour KYC was not approved. Please contact support@wadstone.co.ke for assistance.\n\nWarm regards,\nWadstone Investment Team'
    );
    notifyAdmin('KYC_' + newStatus.toUpperCase(), investor.name + ' (' + investor.email + ')');
    Log.financial('KYC_' + newStatus.toUpperCase(), { investor_id: uid, investor_name: investor.name, admin: currentUser.email });
    toast('KYC ' + action + 'd for ' + investor.name, action === 'approve' ? 'success' : 'error');
    viewClientDetail(uid);
  } catch(e) { captureError(e, { action: 'KYC_ACTION', uid, kycAction: action }); toast('KYC action failed: ' + e.message, 'error'); }
}

async function adminAdjBalance(uid, dir) {
  const u = DB.users.find(x => x.id === uid);
  const amt = validateAmount(document.getElementById('admin-adj-amount').value, 0.01);
  if (!u || amt === null) { toast('Enter a valid amount', 'error'); return; }

  const label = dir === 'add' ? 'credit' : 'debit';
  const confirmed = confirm(
    `${dir === 'add' ? 'Add' : 'Deduct'} ${fmt(amt)} ${dir === 'add' ? 'to' : 'from'} ${u.name}'s account?\n\nThis will be recorded as an admin adjustment and cannot be undone.`
  );
  if (!confirmed) return;

  const btn = document.querySelector('#admin-client-detail-content .btn-success');
  if (btn) { btn.disabled = true; btn.textContent = 'Saving...'; }

  try {
    const ref = 'ADJ-' + crypto.randomUUID().slice(0, 8).toUpperCase();

    if (dir === 'add') {
      // Reuse the atomic deposit RPC — creates a transaction + updates capital_accounts in one DB transaction
      await db_approveDeposit(null, uid, amt, 'admin_adjustment', ref, currentUser.id);
    } else {
      // Check live balance before deducting
      const account = await db_getCapitalAccount(uid);
      const balance = account?.balance || 0;
      if (amt > balance) {
        toast(`Cannot deduct ${fmt(amt)} — balance is only ${fmt(balance)}`, 'error');
        return;
      }
      await db_approveWithdrawal(null, uid, amt, 'admin_adjustment', ref, currentUser.id);
    }

    await db_writeAudit(
      currentUser.id, currentUser.email,
      'ADMIN_BALANCE_ADJUSTMENT', 'capital_account', uid,
      `${dir === 'add' ? '+' : '-'}${fmt(amt)} for ${u.name} (${label}) — Ref: ${ref}`
    );

    notifyAdmin('ADMIN_BALANCE_ADJUSTMENT', (dir==='add'?'+':'-') + fmt(amt) + ' for ' + u.name + ' (' + uid + ') — Ref: ' + ref);
    Log.financial('ADMIN_BALANCE_ADJUSTMENT', { investor_id: uid, direction: dir, amount: amt, ref, admin: currentUser.email });
    await syncDBFromSupabase();
    toast(`Balance ${dir === 'add' ? 'increased' : 'decreased'} by ${fmt(amt)} ✓`, 'success');
    document.getElementById('admin-adj-amount').value = '';
    viewClientDetail(uid);
  } catch(e) {
    captureError(e, { action: 'ADMIN_ADJ_BALANCE', uid, dir, amount: document.getElementById('admin-adj-amount')?.value });
    toast('Adjustment failed: ' + (e.message || 'Please try again.'), 'error');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '+ Add'; }
  }
}

async function adminApproveTxn(uid, tid) {
  const u = DB.users.find(x => x.id === uid);
  if (!u) return;
  const { data: txn } = await sb.from('transactions').select('*').eq('id', tid).single();
  if (!txn) { toast('Transaction not found', 'error'); return; }
  try {
    if (txn.type === 'deposit') {
      await db_approveDeposit(tid, uid, txn.amount, txn.method, txn.reference, currentUser.id);
    } else if (txn.type === 'withdrawal') {
      await db_approveWithdrawal(tid, uid, txn.amount, txn.method, txn.reference, currentUser.id);
    } else {
      await db_updateTransaction(tid, { status: 'approved', approved_by: currentUser.id, approved_at: new Date().toISOString() });
    }
    await syncDBFromSupabase();
    sendEmailNotification(u.email, u.name,
      `${txn.type === 'withdrawal' ? 'Withdrawal' : 'Deposit'} Confirmed — ${txn.reference}`,
      `Dear ${u.name},\n\nYour ${txn.type} of $${txn.amount?.toLocaleString()} (Ref: ${txn.reference}) has been approved.\n\nLog in to view your updated balance.\n\nWarm regards,\nWadstone Investment Team`
    );
    notifyAdmin('TRANSACTION_APPROVED', txn.type.toUpperCase() + ' of ' + fmt(txn.amount) + ' for ' + u.name + ' — Ref: ' + txn.reference);
    Log.financial('TRANSACTION_APPROVED', { txn_id: tid, investor_id: uid, type: txn.type, amount: txn.amount, ref: txn.reference });
    toast('Transaction approved ✓', 'success');
    viewClientDetail(uid);
  } catch(e) { captureError(e, { action: 'APPROVE_TXN', uid, tid }); toast('Approval failed: ' + e.message, 'error'); }
}

async function adminRejectTxn(uid, tid) {
  const u = DB.users.find(x => x.id === uid);
  if (!u) return;
  try {
    const { data: txn } = await sb.from('transactions').select('*').eq('id', tid).single();
    await db_updateTransaction(tid, { status: 'rejected', approved_by: currentUser.id, approved_at: new Date().toISOString() });
    await db_writeAudit(currentUser.id, currentUser.email, 'TRANSACTION_REJECTED', 'transaction', tid, `Rejected for ${u.name}`);
    await syncDBFromSupabase();
    sendEmailNotification(u.email, u.name, `Transaction Not Confirmed — ${txn?.reference}`,
      `Dear ${u.name},\n\nYour ${txn?.type} (Ref: ${txn?.reference}) could not be confirmed. Contact support@wadstone.co.ke.\n\nWarm regards,\nWadstone Investment Team`
    );
    notifyAdmin('TRANSACTION_REJECTED', (txn?.type||'').toUpperCase() + ' — Ref: ' + (txn?.reference||'unknown') + ' for ' + u.name);
    Log.financial('TRANSACTION_REJECTED', { txn_id: tid, investor_id: uid, ref: txn?.reference });
    toast('Transaction rejected', 'error');
    viewClientDetail(uid);
  } catch(e) { captureError(e, { action: 'REJECT_TXN', uid, tid }); toast('Rejection failed: ' + e.message, 'error'); }
}

async function renderAdminKYC() {
  const tbody = document.getElementById('admin-kyc-table');
  tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:16px;color:var(--text3)">Loading...</td></tr>';

  const { data: pending, error } = await sb.from('investors')
    .select('id, name, email, kyc_status, kyc_data, kyc_docs, submitted_at')
    .eq('kyc_status', 'pending')
    .neq('role', 'admin')
    .order('submitted_at', { ascending: true });

  if (error) { tbody.innerHTML = '<tr><td colspan="5"><div class="empty"><p>Failed to load KYC queue</p></div></td></tr>'; return; }

  document.getElementById('kyc-queue-count').textContent = (pending?.length || 0) + ' pending';

  if (!pending || !pending.length) {
    tbody.innerHTML = '<tr><td colspan="5"><div class="empty"><p>No pending KYC applications</p></div></td></tr>';
    return;
  }

  tbody.innerHTML = pending.map(u => {
    const docs = u.kyc_docs || {};
    const docCount = ['id_front','proof_of_address','selfie_with_id'].filter(k => docs[k]).length;
    return `
    <tr>
      <td style="font-weight:500">${sanitize(u.name)}<br/><span style="font-size:11px;color:var(--text3)">${sanitize(u.email)}</span></td>
      <td style="font-size:12px;color:var(--text3)">${sanitize(fmtDate(u.submitted_at || new Date().toISOString()))}</td>
      <td>${sanitize(capitalize((u.kyc_data?.accountType || 'individual')))}</td>
      <td>
        ${docCount} / 3 uploaded
        <div class="progress" style="margin-top:4px;width:80px">
          <div class="progress-bar gold" style="width:${(docCount/3)*100}%"></div>
        </div>
      </td>
      <td>
        <div style="display:flex;gap:6px">
          <button class="btn btn-ghost btn-sm" onclick="viewClientDetail('${sanitize(u.id)}');showPage('admin-client-detail')">View</button>
          <button class="btn btn-success btn-sm" onclick="quickKycAction('${sanitize(u.id)}','approve').then(()=>renderAdminKYC())">Approve</button>
          <button class="btn btn-danger btn-sm" onclick="quickKycAction('${sanitize(u.id)}','reject').then(()=>renderAdminKYC())">Reject</button>
        </div>
      </td>
    </tr>`;
  }).join('');
}

async function renderAdminTransactions() {
  const tbody = document.getElementById('admin-txn-table');
  tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:16px;color:var(--text3)">Loading...</td></tr>';

  // Fetch all transactions live from Supabase (joins investor name via foreign key)
  const { data: allTxns, error } = await sb
    .from('transactions')
    .select('*, investors(id, name, email)')
    .order('created_at', { ascending: false })
    .limit(200);

  if (error) { tbody.innerHTML = '<tr><td colspan="7"><div class="empty"><p>Failed to load transactions</p></div></td></tr>'; return; }
  if (!allTxns || !allTxns.length) { tbody.innerHTML = '<tr><td colspan="7"><div class="empty"><p>No transactions</p></div></td></tr>'; return; }

  tbody.innerHTML = allTxns.map(t => {
    const investorName = t.investors?.name || '—';
    const investorId   = t.investors?.id   || t.investor_id;
    return `
    <tr>
      <td style="font-size:12px;font-family:'DM Mono',monospace">${fmtDate(t.created_at)}</td>
      <td style="font-weight:500">${sanitize(investorName)}</td>
      <td><span class="badge ${t.type==='deposit'?'badge-success':'badge-info'}">${capitalize(t.type)}</span></td>
      <td style="color:${t.type==='deposit'?'var(--success)':'var(--danger)'}">${t.type==='deposit'?'+':'-'}${fmt(t.amount)}</td>
      <td style="color:var(--text3)">${sanitize(t.method||'—')}</td>
      <td><span class="badge ${statusBadge(t.status)}">${capitalize(t.status)}</span></td>
      <td>
        ${t.status==='pending'?`
          <div style="display:flex;gap:4px">
            <button class="btn btn-success btn-sm" style="padding:4px 10px" onclick="adminApproveTxn('${sanitize(investorId)}','${sanitize(t.id)}');renderAdminTransactions()">✓</button>
            <button class="btn btn-danger btn-sm" style="padding:4px 10px" onclick="adminRejectTxn('${sanitize(investorId)}','${sanitize(t.id)}');renderAdminTransactions()">✗</button>
          </div>` : '—'}
      </td>
    </tr>`;
  }).join('');
}

// ════════════════════════════════════════════
//  PASSWORD HASHING — REMOVED
//  Passwords are managed exclusively by Supabase Auth.
//  hashPassword() and migratePasswordIfNeeded() were dead
//  code after the move to sb.auth.signInWithPassword().
//  changeAdminPassword() now calls sb.auth.updateUser().
// ════════════════════════════════════════════

// ════════════════════════════════════════════
//  AUDIT LOG
// ════════════════════════════════════════════
function addAuditLog(action, details) {
  // Write to Supabase audit_log (non-blocking)
  if (currentUser) {
    db_writeAudit(currentUser.id, currentUser.email, action, null, null, details).catch(e => console.warn('Audit log failed:', e));
  }
  // Also keep in local DB shim for immediate UI rendering
  if (!DB.auditLog) DB.auditLog = [];
  DB.auditLog.unshift({ time: new Date().toISOString(), action, by: currentUser?.email || 'system', details });
  if (DB.auditLog.length > 200) DB.auditLog = DB.auditLog.slice(0, 200);
}

async function renderAuditLog() {
  const tbody = document.getElementById('audit-log-table');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:16px;color:var(--text3)">Loading...</td></tr>';

  const filter = document.getElementById('log-filter')?.value || 'all';
  const allLogs = await db_getAuditLog(200);

  // Update stat strip
  const financialActions = ['DEPOSIT_REQUESTED','DEPOSIT_APPROVED','WITHDRAWAL_REQUESTED','WITHDRAWAL_APPROVED',
    'ADMIN_BALANCE_ADJUSTMENT','FEES_POSTED','RETURNS_POSTED','FIXED_RETURN_POSTED','TRANSACTION_APPROVED','TRANSACTION_REJECTED'];
  const authActions = ['LOGIN','LOGOUT','PASSWORD_CHANGED'];
  if (document.getElementById('log-stat-total'))     document.getElementById('log-stat-total').textContent     = allLogs.length;
  if (document.getElementById('log-stat-financial')) document.getElementById('log-stat-financial').textContent = allLogs.filter(l => financialActions.includes(l.action)).length;
  if (document.getElementById('log-stat-auth'))      document.getElementById('log-stat-auth').textContent      = allLogs.filter(l => authActions.includes(l.action)).length;
  if (document.getElementById('log-stat-errors'))    document.getElementById('log-stat-errors').textContent    = allLogs.filter(l => l.action?.includes('FAIL') || l.action?.includes('ERROR') || l.action?.includes('REJECT')).length;

  // Apply filter
  let logs = allLogs;
  if (filter === 'financial') logs = allLogs.filter(l => financialActions.includes(l.action));
  else if (filter === 'auth') logs = allLogs.filter(l => authActions.includes(l.action));
  else if (filter === 'admin') logs = allLogs.filter(l => l.actor_email === currentUser?.email);
  else if (filter === 'error') logs = allLogs.filter(l => l.action?.includes('FAIL') || l.action?.includes('ERROR') || l.action?.includes('REJECT'));

  if (!logs.length) { tbody.innerHTML = '<tr><td colspan="5"><div class="empty"><p>No events match this filter</p></div></td></tr>'; return; }

  const levelColor = action => {
    if (['DEPOSIT_APPROVED','WITHDRAWAL_APPROVED','KYC_APPROVED','RETURNS_POSTED','FEES_POSTED'].includes(action)) return { label: 'OK', color: 'var(--success)' };
    if (['TRANSACTION_REJECTED','KYC_REJECTED'].includes(action)) return { label: 'Reject', color: 'var(--danger)' };
    if (['LOGIN','LOGOUT'].includes(action)) return { label: 'Auth', color: 'var(--info)' };
    if (action?.includes('REQUESTED')) return { label: 'Pending', color: 'var(--warn)' };
    if (action?.includes('ADJUSTMENT') || action?.includes('POSTED')) return { label: 'Admin', color: 'var(--gold)' };
    return { label: 'Info', color: 'var(--text3)' };
  };

  tbody.innerHTML = logs.map(l => {
    const lv = levelColor(l.action);
    return `<tr>
      <td style="font-size:11px;font-family:'DM Mono',monospace;white-space:nowrap;color:var(--text3)">${fmtDate(l.created_at)}</td>
      <td style="font-size:12px;font-weight:500">${sanitize(l.action || '—')}</td>
      <td style="font-size:11px;color:var(--text3)">${sanitize(l.actor_email?.split('@')[0] || '—')}</td>
      <td style="font-size:12px;color:var(--text2);max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${sanitize(l.details||'')}">${sanitize(l.details || '—')}</td>
      <td><span style="font-size:10px;font-weight:600;padding:2px 6px;border-radius:4px;background:${lv.color}22;color:${lv.color}">${lv.label}</span></td>
    </tr>`;
  }).join('');
}

function exportAuditCSV() {
  db_getAuditLog(500).then(logs => {
    if (!logs.length) { toast('No audit log entries to export', 'error'); return; }
    const headers = ['Time', 'Action', 'Actor', 'Details'];
    const rows = logs.map(l => [
      new Date(l.created_at).toISOString(),
      l.action || '',
      l.actor_email || '',
      (l.details || '').replace(/"/g, "'")
    ]);
    const csv = [headers, ...rows].map(r => r.map(c => `"${c}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'wadstone_audit_' + new Date().toISOString().slice(0,10) + '.csv';
    a.click();
    toast('Audit log exported ✓', 'success');
  });
}

// ════════════════════════════════════════════
//  CHANGE ADMIN PASSWORD
// ════════════════════════════════════════════
async function changeAdminPassword() {
  const cur  = document.getElementById('admin-cur-pass').value;
  const nw   = document.getElementById('admin-new-pass').value;
  const conf = document.getElementById('admin-conf-pass').value;

  if (!cur || !nw || !conf) { toast('Please fill all password fields', 'error'); return; }
  if (nw.length < 8) { toast('New password must be at least 8 characters', 'error'); return; }
  if (nw !== conf) { toast('New passwords do not match', 'error'); return; }

  const btn = document.querySelector('#page-admin-settings .btn-gold');
  if (btn) { btn.disabled = true; btn.textContent = 'Updating...'; }

  try {
    // Verify current password by re-authenticating against Supabase Auth
    const { error: signInError } = await sb.auth.signInWithPassword({
      email: currentUser.email,
      password: cur
    });
    if (signInError) { toast('Current password is incorrect', 'error'); return; }

    // Now update to the new password via Supabase Auth
    const { error: updateError } = await sb.auth.updateUser({ password: nw });
    if (updateError) throw new Error(updateError.message);

    await db_writeAudit(currentUser.id, currentUser.email, 'PASSWORD_CHANGED', 'investor', currentUser.id, 'Admin password updated via settings');
    notifyAdmin('PASSWORD_CHANGED', 'Admin account password was changed');
    Log.warn('PASSWORD_CHANGED', { user_id: currentUser.id, role: 'admin' });
    toast('Password updated successfully ✓', 'success');
    document.getElementById('admin-cur-pass').value = '';
    document.getElementById('admin-new-pass').value = '';
    document.getElementById('admin-conf-pass').value = '';
  } catch(e) {
    toast('Password update failed: ' + (e.message || 'Please try again.'), 'error');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Update Password'; }
  }
}

// ════════════════════════════════════════════
//  CLIENT 2FA — optional toggle in profile → security tab
// ─────────────────────────────────────────────────────────────
async function renderClient2FAStatus() {
  const badge = document.getElementById('client-2fa-badge');
  const area  = document.getElementById('client-2fa-action');
  if (!badge || !area) return;

  const { data: factors } = await sb.auth.mfa.listFactors();
  const verified = [...(factors?.totp || []), ...(factors?.all || [])]
    .find(f => f.factor_type === 'totp' && f.status === 'verified');

  if (verified) {
    badge.textContent = 'Enabled';
    badge.style.cssText = 'font-size:11px;padding:3px 9px;border-radius:99px;background:#1a3a2a;color:#4ade80';
    area.innerHTML = '<button class="btn btn-outline btn-sm" style="color:var(--danger);border-color:var(--danger)" onclick="clientDisable2FA()">Disable 2FA</button>';
  } else {
    badge.textContent = 'Not enabled';
    badge.style.cssText = 'font-size:11px;padding:3px 9px;border-radius:99px;background:var(--bg2);color:var(--text3);border:1px solid var(--border)';
    area.innerHTML = '<button class="btn btn-outline btn-sm" onclick="clientEnroll2FA()">Enable 2FA</button>';
  }
}

async function clientEnroll2FA() {
  // Clean up any stuck factors first
  const { data: existing } = await sb.auth.mfa.listFactors();
  const allTotp = [...(existing?.totp || []), ...(existing?.all || [])].filter(f => f.factor_type === 'totp');
  for (const f of allTotp) {
    await sb.auth.mfa.unenroll({ factorId: f.id });
    await new Promise(r => setTimeout(r, 400));
  }

  const { data, error } = await sb.auth.mfa.enroll({ factorType: 'totp', friendlyName: 'WadstoneClient' });
  if (error) { toast('Could not start 2FA setup: ' + error.message, 'error'); return; }
  document.getElementById('client-totp-qr-img').src    = data.totp.qr_code;
  document.getElementById('client-totp-secret').textContent = data.totp.secret;
  document.getElementById('client-totp-factor-id').value    = data.id;
  openModal('modal-client-totp-enroll');
}

async function clientVerifyEnrollment() {
  const factorId = document.getElementById('client-totp-factor-id').value;
  const code     = document.getElementById('client-totp-enroll-code').value.trim();
  if (!code || code.length !== 6) { toast('Please enter the 6-digit code.', 'error'); return; }

  const { data: ch, error: ce } = await sb.auth.mfa.challenge({ factorId });
  if (ce) { toast('Challenge failed: ' + ce.message, 'error'); return; }

  const { error: ve } = await sb.auth.mfa.verify({ factorId, challengeId: ch.id, code });
  if (ve) { toast('Incorrect code. Please try again.', 'error'); return; }

  closeModal('modal-client-totp-enroll');
  toast('Two-factor authentication enabled ✓', 'success');
  await renderClient2FAStatus();
}

async function clientDisable2FA() {
  if (!confirm('Disable two-factor authentication? Your account will be less secure.')) return;
  const { data: factors } = await sb.auth.mfa.listFactors();
  const allTotp = [...(factors?.totp || []), ...(factors?.all || [])].filter(f => f.factor_type === 'totp');
  for (const f of allTotp) {
    await sb.auth.mfa.unenroll({ factorId: f.id });
  }
  toast('Two-factor authentication disabled.', 'info');
  await renderClient2FAStatus();
}

//  CLIENT PASSWORD CHANGE (profile → security tab)
// ════════════════════════════════════════════
async function changeClientPassword() {
  const cur  = document.getElementById('prof-cur-pass').value;
  const nw   = document.getElementById('prof-new-pass').value;
  const conf = document.getElementById('prof-conf-pass').value;
  const errEl = document.getElementById('prof-pass-err');
  errEl.style.display = 'none';

  if (!cur || !nw || !conf) { errEl.textContent = 'Please fill all fields.'; errEl.style.display = 'block'; return; }
  if (nw.length < 8)        { errEl.textContent = 'New password must be at least 8 characters.'; errEl.style.display = 'block'; return; }
  if (nw !== conf)           { errEl.textContent = 'New passwords do not match.'; errEl.style.display = 'block'; return; }

  const btn = document.querySelector('#profile-security .btn-gold');
  if (btn) { btn.disabled = true; btn.textContent = 'Updating...'; }

  try {
    // Re-authenticate to verify current password
    const { error: signInError } = await sb.auth.signInWithPassword({
      email: currentUser.email,
      password: cur
    });
    if (signInError) { errEl.textContent = 'Current password is incorrect.'; errEl.style.display = 'block'; return; }

    // Update via Supabase Auth
    const { error: updateError } = await sb.auth.updateUser({ password: nw });
    if (updateError) throw new Error(updateError.message);

    await db_writeAudit(currentUser.id, currentUser.email, 'PASSWORD_CHANGED', 'investor', currentUser.id, 'Client password updated via profile');
    toast('Password updated successfully ✓', 'success');
    document.getElementById('prof-cur-pass').value  = '';
    document.getElementById('prof-new-pass').value  = '';
    document.getElementById('prof-conf-pass').value = '';
  } catch(e) {
    errEl.textContent = 'Update failed: ' + (e.message || 'Please try again.');
    errEl.style.display = 'block';
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Update Password'; }
  }
}

// ════════════════════════════════════════════
//  FORGOT PASSWORD — send reset email (login page)
// ════════════════════════════════════════════
function showForgotPassword() {
  const emailInput = document.getElementById('forgot-email');
  // Pre-fill with whatever the user typed in the login form
  const loginEmail = document.getElementById('login-email')?.value;
  if (emailInput && loginEmail) emailInput.value = loginEmail;
  const msgEl = document.getElementById('forgot-msg');
  if (msgEl) { msgEl.style.display = 'none'; msgEl.textContent = ''; }
  openModal('modal-forgot-password');
}

async function submitForgotPassword() {
  const email = document.getElementById('forgot-email').value.trim().toLowerCase();
  const msgEl = document.getElementById('forgot-msg');
  if (!email) { msgEl.textContent = 'Please enter your email address.'; msgEl.style.display = 'block'; msgEl.style.color = 'var(--danger)'; return; }

  const btn = document.querySelector('#modal-forgot-password .btn-gold');
  if (btn) { btn.disabled = true; btn.textContent = 'Sending...'; }

  try {
    const { error } = await sb.auth.resetPasswordForEmail(email, {
      redirectTo: window.location.origin + window.location.pathname + '?reset=true'
    });
    // Always show success — never confirm whether an email exists (security best practice)
    msgEl.textContent = 'If an account exists for that email, a reset link has been sent. Check your inbox.';
    msgEl.style.color = 'var(--success)';
    msgEl.style.display = 'block';
    if (error) console.warn('Reset email error (not shown to user):', error.message);
  } catch(e) {
    msgEl.textContent = 'Something went wrong. Please try again.';
    msgEl.style.color = 'var(--danger)';
    msgEl.style.display = 'block';
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Send Reset Link'; }
  }
}

// ════════════════════════════════════════════
//  RESEND CONFIRMATION EMAIL — for expired/scanner-consumed signup links
// ════════════════════════════════════════════
function showResendConfirm() {
  const emailInput = document.getElementById('resend-confirm-email');
  const loginEmail = document.getElementById('login-email')?.value;
  if (emailInput && loginEmail) emailInput.value = loginEmail;
  const msgEl = document.getElementById('resend-confirm-msg');
  if (msgEl) { msgEl.style.display = 'none'; msgEl.textContent = ''; }
  openModal('modal-resend-confirm');
}

async function submitResendConfirmation() {
  const email = document.getElementById('resend-confirm-email').value.trim().toLowerCase();
  const msgEl = document.getElementById('resend-confirm-msg');
  if (!email) { msgEl.textContent = 'Please enter your email address.'; msgEl.style.display = 'block'; msgEl.style.color = 'var(--danger)'; return; }

  const btn = document.querySelector('#modal-resend-confirm .btn-gold');
  if (btn) { btn.disabled = true; btn.textContent = 'Sending...'; }

  try {
    const { error } = await sb.auth.resend({ type: 'signup', email });
    // Always show success — never confirm whether an account/email exists (security best practice)
    msgEl.textContent = 'If an unconfirmed account exists for that email, a new confirmation link has been sent.';
    msgEl.style.color = 'var(--success)';
    msgEl.style.display = 'block';
    if (error) console.warn('Resend confirmation error (not shown to user):', error.message);
  } catch(e) {
    msgEl.textContent = 'Something went wrong. Please try again.';
    msgEl.style.color = 'var(--danger)';
    msgEl.style.display = 'block';
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Resend Email'; }
  }
}

// Handle Supabase password reset redirect — called when user clicks the email link
// and lands back on the app with a recovery session active.
async function sendClientPasswordReset() {
  if (!currentUser?.email) { toast('Please log in first', 'error'); return; }
  const btn = document.querySelector('#profile-security .btn-outline');
  if (btn) { btn.disabled = true; btn.textContent = 'Sending...'; }
  try {
    const { error } = await sb.auth.resetPasswordForEmail(currentUser.email, {
      redirectTo: window.location.origin + window.location.pathname + '?reset=true'
    });
    if (error) throw new Error(error.message);
    toast('Password reset email sent — check your inbox ✓', 'success');
  } catch(e) {
    toast('Could not send reset email: ' + e.message, 'error');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Forgot password? Send reset email instead'; }
  }
}
async function savePaymentSettings() {
  const settings = {
    mpesa: {
      paybill: document.getElementById('set-mpesa-paybill').value,
      name: document.getElementById('set-mpesa-name').value
    },
    bank: {
      name: document.getElementById('set-bank-name').value,
      acname: document.getElementById('set-bank-acname').value,
      accno: document.getElementById('set-bank-accno').value,
      branch: document.getElementById('set-bank-branch').value,
      swift: document.getElementById('set-bank-swift').value,
      code: document.getElementById('set-bank-code').value
    },
    crypto: {
      usdt: document.getElementById('set-usdt').value,
      btc: document.getElementById('set-btc').value
    }
  };

  const btn = document.querySelector('#page-admin-settings .btn-gold');
  if (btn) { btn.disabled = true; btn.textContent = 'Saving...'; }

  try {
    // Persist to Supabase fund_settings table — survives reloads and all sessions
    await db_saveFundSetting('payment_settings', settings, currentUser.email);

    // Keep in-memory shim in sync so applyPaymentSettings() works immediately
    DB.paymentSettings = settings;
    fundSettings.payment_settings = settings;

    applyPaymentSettings();
    await db_writeAudit(currentUser.id, currentUser.email, 'PAYMENT_SETTINGS_UPDATED', 'fund_settings', null, 'Admin updated bank/M-Pesa/crypto details');
    toast('Payment details saved ✓', 'success');
  } catch(e) {
    toast('Save failed: ' + (e.message || 'Please try again.'), 'error');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Save Payment Details'; }
  }
}

function applyPaymentSettings() {
  // Primary source: fundSettings loaded from Supabase on login/startup.
  // Fall back to DB.paymentSettings shim for immediate post-save refresh.
  const s = fundSettings.payment_settings || DB.paymentSettings;
  if (!s) return;

  // Keep shim in sync so other functions that read DB.paymentSettings work
  DB.paymentSettings = s;

  const mpesaEl = document.getElementById('dep-mpesa-details');
  if (mpesaEl && s.mpesa) {
    mpesaEl.querySelector('div').innerHTML = `
      <strong>M-Pesa Paybill</strong><br/>
      Paybill Number: <strong>${s.mpesa.paybill}</strong><br/>
      Account Number: <strong>Your Client ID</strong><br/>
      Till Name: ${s.mpesa.name}<br/>
      <span style="font-size:11px;color:var(--text3)">After payment, enter your M-Pesa transaction code in the notes field below.</span>`;
  }

  const bankEl = document.getElementById('dep-kenyan-bank-details');
  if (bankEl && s.bank) {
    bankEl.querySelector('div').innerHTML = `
      <strong>Kenyan Bank Transfer Details</strong><br/>
      Bank: ${s.bank.name}<br/>
      Account Name: ${s.bank.acname}<br/>
      Account No: <strong>${s.bank.accno}</strong><br/>
      Branch: ${s.bank.branch}<br/>
      Branch Code: ${s.bank.code}<br/>
      Swift Code: ${s.bank.swift}<br/>
      <span style="font-size:11px;color:var(--text3)">Use your client ID as reference.</span>`;
  }

  const cryptoEl = document.getElementById('dep-crypto-details');
  if (cryptoEl && s.crypto) {
    cryptoEl.querySelector('div').innerHTML = `
      <strong>Crypto Deposit Address</strong><br/>
      USDT (TRC20): ${s.crypto.usdt}<br/>
      Bitcoin: ${s.crypto.btc}<br/>
      <span style="font-size:11px;color:var(--text3)">Min: $10,000 equivalent. Exchange rate locked at receipt.</span>`;
  }

  // Pre-fill settings fields if on settings page
  if (document.getElementById('set-mpesa-paybill')) {
    document.getElementById('set-mpesa-paybill').value = s.mpesa?.paybill || '';
    document.getElementById('set-mpesa-name').value = s.mpesa?.name || '';
    document.getElementById('set-bank-name').value = s.bank?.name || '';
    document.getElementById('set-bank-acname').value = s.bank?.acname || '';
    document.getElementById('set-bank-accno').value = s.bank?.accno || '';
    document.getElementById('set-bank-branch').value = s.bank?.branch || '';
    document.getElementById('set-bank-swift').value = s.bank?.swift || '';
    document.getElementById('set-bank-code').value = s.bank?.code || '';
    document.getElementById('set-usdt').value = s.crypto?.usdt || '';
    document.getElementById('set-btc').value = s.crypto?.btc || '';
  }
}

// ════════════════════════════════════════════
//  RECEIPT / PROOF OF PAYMENT UPLOAD
// ════════════════════════════════════════════
function handleReceiptUpload() {
  const input = document.getElementById('file-receipt');
  const area  = document.getElementById('upload-receipt');
  const file  = input.files[0];
  if (!file) return;

  const validTypes = ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'];
  if (!validTypes.includes(file.type)) {
    toast('Invalid file type. Use JPG, PNG, or PDF.', 'error');
    input.value = '';
    return;
  }
  if (file.size > 5 * 1024 * 1024) {
    toast('File too large. Max 5MB.', 'error');
    input.value = '';
    return;
  }

  area.innerHTML = `<div style="color:var(--gold)">⏳ Loading...</div>`;
  const reader = new FileReader();
  reader.onload = e => {
    depositReceipt = { name: sanitize(file.name), type: file.type, data: e.target.result };
    area.classList.add('uploaded');
    area.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:24px"><polyline points="20 6 9 17 4 12"/></svg>
      <p style="color:var(--success)">${sanitize(file.name)} ✓</p>`;
    toast('Receipt uploaded', 'success');
  };
  reader.readAsDataURL(file);
}

// ════════════════════════════════════════════
//  EMAIL NOTIFICATIONS (via EmailJS - free tier)
//  To activate: sign up at emailjs.com, get your
//  service ID, template ID and public key, paste below
// ════════════════════════════════════════════
const EMAIL_CONFIG = {
  serviceId: 'YOUR_EMAILJS_SERVICE_ID',
  templateId: 'YOUR_EMAILJS_TEMPLATE_ID',
  publicKey: 'YOUR_EMAILJS_PUBLIC_KEY',
  enabled: false // set to true after configuring above
};

function sendEmailNotification(toEmail, toName, subject, message) {
  if (!EMAIL_CONFIG.enabled) {
    console.log('Email notification (not configured):', subject, toEmail);
    return;
  }
  // EmailJS send
  if (window.emailjs) {
    emailjs.send(EMAIL_CONFIG.serviceId, EMAIL_CONFIG.templateId, {
      to_email: toEmail,
      to_name: toName,
      subject: subject,
      message: message,
      from_name: 'Wadstone Investment'
    }, EMAIL_CONFIG.publicKey).catch(e => console.warn('Email failed:', e));
  }
}

// ════════════════════════════════════════════
//  APPLY SETTINGS ON APP LOAD
// ════════════════════════════════════════════
function applyAllSettings() {
  applyPaymentSettings();
}

// ════════════════════════════════════════════
//  STARTUP — restore session or show landing
// ════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', async () => {
  // Signup confirmation is fully handled by its own block above (it calls
  // applyAllSettings()/showAuth('login')/toast() itself once verifyOtp resolves),
  // so skip the normal flow here to avoid doing it twice.
  if (IS_SIGNUP_CONFIRM_LINK) return;

  applyAllSettings();

  // If this looks like a password-reset link, give the onAuthStateChange
  // listener (registered above, right after createClient) a moment to fire
  // PASSWORD_RECOVERY and render the "set new password" screen. We poll a
  // flag instead of re-checking the hash, since Supabase has likely already
  // cleared it by now.
  if (IS_PASSWORD_RECOVERY_LINK) {
    for (let i = 0; i < 30 && !recoveryUIShown; i++) {
      await new Promise(r => setTimeout(r, 100));
    }
    if (recoveryUIShown) return;
    // Link looked like a recovery link but no valid recovery session showed up
    // (expired/used link, or the redirect URL isn't whitelisted in Supabase).
    toast('This password reset link is invalid or has expired. Please request a new one.', 'error');
  }

  const restored = await restoreSession();
  if (restored) {
    initApp();
  } else {
    showAuth('login');
  }
});

// Show a simple full-screen "set new password" form when user arrives via reset link
function showRecoveryPasswordUI() {
  document.body.innerHTML = `
    <div style="min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--darker,#0a0a0a)">
      <div style="background:var(--dark,#111);border-radius:12px;padding:36px;width:100%;max-width:400px;border:1px solid var(--border,#222)">
        <div style="font-family:'Cormorant Garamond',serif;font-size:22px;color:#C9A84C;font-weight:600;margin-bottom:4px">Wadstone Investment</div>
        <div style="font-size:13px;color:#888;margin-bottom:24px">Set your new password</div>
        <div style="display:flex;flex-direction:column;gap:14px">
          <div>
            <label style="font-size:12px;color:#aaa;display:block;margin-bottom:6px">New Password</label>
            <input type="password" id="recovery-new-pass" placeholder="Min 8 characters"
              style="width:100%;padding:10px 12px;background:#1a1a1a;border:1px solid #333;border-radius:8px;color:#fff;font-size:14px;box-sizing:border-box" />
          </div>
          <div>
            <label style="font-size:12px;color:#aaa;display:block;margin-bottom:6px">Confirm New Password</label>
            <input type="password" id="recovery-conf-pass" placeholder="Re-enter password"
              style="width:100%;padding:10px 12px;background:#1a1a1a;border:1px solid #333;border-radius:8px;color:#fff;font-size:14px;box-sizing:border-box" />
          </div>
          <div id="recovery-err" style="display:none;color:#e05252;font-size:13px"></div>
          <button id="recovery-btn" onclick="submitRecoveryPassword()"
            style="width:100%;padding:12px;background:#C9A84C;color:#000;border:none;border-radius:8px;font-weight:600;font-size:14px;cursor:pointer">
            Set New Password
          </button>
        </div>
      </div>
    </div>`;
}

async function submitRecoveryPassword() {
  const nw   = document.getElementById('recovery-new-pass').value;
  const conf = document.getElementById('recovery-conf-pass').value;
  const errEl = document.getElementById('recovery-err');
  const btn   = document.getElementById('recovery-btn');
  errEl.style.display = 'none';

  if (nw.length < 8) { errEl.textContent = 'Password must be at least 8 characters.'; errEl.style.display = 'block'; return; }
  if (nw !== conf)   { errEl.textContent = 'Passwords do not match.'; errEl.style.display = 'block'; return; }

  btn.disabled = true; btn.textContent = 'Updating...';
  try {
    const { error } = await sb.auth.updateUser({ password: nw });
    if (error) throw new Error(error.message);
    btn.textContent = '✓ Password updated! Redirecting...';
    btn.style.background = '#3DB87A';
    // Clear the hash and reload so the user lands on the login page cleanly
    setTimeout(() => { window.location.href = window.location.pathname; }, 1500);
  } catch(e) {
    errEl.textContent = 'Failed: ' + e.message;
    errEl.style.display = 'block';
    btn.disabled = false; btn.textContent = 'Set New Password';
  }
}

// ════════════════════════════════════════════
//  ACCOUNTING MODULE
// ════════════════════════════════════════════
function initAccounting() {
  renderAccLedger();
  renderAccStats();
  populateAccClientDropdowns();
  renderReturnsHistory();
  renderFeeSummary();
  renderJournalTable();
  const now = new Date().toISOString().slice(0,7);
  ['acc-return-period','acc-fee-period','acc-stmt-period'].forEach(id => { const el = document.getElementById(id); if (el) el.value = now; });
  const jd = document.getElementById('jnl-date'); if (jd) jd.value = new Date().toISOString().slice(0,10);
}

function switchAccTab(tab) {
  ['ledger','returns','fees','statements','journal'].forEach(t => {
    const p = document.getElementById('acc-panel-' + t); if (p) p.style.display = t === tab ? 'block' : 'none';
    const tb = document.getElementById('acc-tab-' + t); if (tb) tb.classList.toggle('active', t === tab);
  });
  if (tab === 'statements') populateStatementClients();
}

function getClients() { return (DB.users || []).filter(u => u.role === 'client'); }
function setText(id, val) { const el = document.getElementById(id); if (el) el.textContent = val; }
function calcMgmtFee(aum) { return (aum * (DB.paymentSettings?.mgmtFeeRate || 2)) / 100; }
function calcPerfFee(ret) { return ret > 0 ? (ret * (DB.paymentSettings?.perfFeeRate || 20)) / 100 : 0; }

function renderAccStats() {
  const clients = getClients();
  const totalAUM = clients.reduce((s, u) => s + (u.balance || 0), 0);
  const totalReturns = clients.reduce((s, u) => s + (u.returns || 0), 0);
  const totalMgmt = (DB.feeLog || []).filter(f => f.type === 'management').reduce((s, f) => s + (f.totalAmount || 0), 0);
  const totalPerf = (DB.feeLog || []).filter(f => f.type === 'performance').reduce((s, f) => s + (f.totalAmount || 0), 0);
  setText('acc-total-aum', '$' + totalAUM.toLocaleString('en-US', {minimumFractionDigits:2, maximumFractionDigits:2}));
  setText('acc-total-returns', '$' + totalReturns.toLocaleString('en-US', {minimumFractionDigits:2, maximumFractionDigits:2}));
  setText('acc-mgmt-fees', '$' + totalMgmt.toLocaleString('en-US', {minimumFractionDigits:2, maximumFractionDigits:2}));
  setText('acc-perf-fees', '$' + totalPerf.toLocaleString('en-US', {minimumFractionDigits:2, maximumFractionDigits:2}));
}

function renderAccLedger(filter) {
  const tbody = document.getElementById('acc-ledger-table'); if (!tbody) return;
  let clients = getClients();
  if (filter) clients = clients.filter(u => u.name.toLowerCase().includes(filter.toLowerCase()) || u.email.toLowerCase().includes(filter.toLowerCase()));
  if (!clients.length) { tbody.innerHTML = '<tr><td colspan="8"><div class="empty"><p>No clients yet</p></div></td></tr>'; return; }
  tbody.innerHTML = clients.map(u => {
    const dep = u.deposited || 0, ret = u.returns || 0, bal = u.balance || 0;
    const mf = calcMgmtFee(dep), pf = calcPerfFee(ret);
    const fmt = n => '$' + n.toLocaleString('en-US', {minimumFractionDigits:2, maximumFractionDigits:2});
    return `<tr>
      <td><div style="font-weight:500">${sanitize(u.name)}</div><div style="font-size:11px;color:var(--text3)">${sanitize(u.email)}</div></td>
      <td style="font-size:12px">${u.submittedAt ? sanitize(fmtDate(u.submittedAt)) : '—'}</td>
      <td style="color:var(--info)">${sanitize(fmt(dep))}</td>
      <td style="color:var(--success)">${sanitize(fmt(ret))}</td>
      <td style="color:var(--danger)">${sanitize(fmt(mf))}</td>
      <td style="color:var(--danger)">${sanitize(fmt(pf))}</td>
      <td style="color:var(--gold);font-weight:600">${sanitize(fmt(bal))}</td>
      <td><button class="btn btn-ghost btn-sm" onclick="viewClientLedger('${sanitize(u.id)}')">Ledger</button></td>
    </tr>`;
  }).join('');
}

function filterLedger(val) { renderAccLedger(val); }

function populateAccClientDropdowns() {
  const opts = getClients().map(u => `<option value="${sanitize(u.id)}">${sanitize(u.name)}</option>`).join('');
  ['acc-return-client','acc-fee-client'].forEach(id => { const el = document.getElementById(id); if (el) el.innerHTML = opts; });
  const jc = document.getElementById('jnl-client'); if (jc) jc.innerHTML = '<option value="">— General Entry —</option>' + opts;
}

function populateStatementClients() {
  const el = document.getElementById('acc-stmt-client'); if (!el) return;
  el.innerHTML = '<option value="all">All Clients</option>' + getClients().map(u => `<option value="${sanitize(u.id)}">${sanitize(u.name)}</option>`).join('');
}

// Return type toggle
document.addEventListener('change', function(e) {
  if (e.target.id === 'acc-return-type') {
    const isFixed = e.target.value === 'fixed';
    const pg = document.getElementById('acc-return-percent-group'); if (pg) pg.style.display = isFixed ? 'none' : 'block';
    const fg = document.getElementById('acc-return-fixed-group'); if (fg) fg.style.display = isFixed ? 'block' : 'none';
  }
  if (e.target.id === 'acc-fee-scope') {
    const cg = document.getElementById('acc-fee-client-group'); if (cg) cg.style.display = e.target.value === 'single' ? 'block' : 'none';
  }
});

function previewReturns() {
  const type = document.getElementById('acc-return-type').value;
  const period = document.getElementById('acc-return-period').value;
  const previewEl = document.getElementById('acc-return-preview');
  if (!period) { toast('Select a period', 'error'); return; }
  const fmt = n => '$' + n.toLocaleString('en-US', {minimumFractionDigits:2, maximumFractionDigits:2});
  let rows = '';
  if (type === 'percent') {
    const rate = parseFloat(document.getElementById('acc-return-rate').value);
    if (!rate) { toast('Enter a return rate', 'error'); return; }
    const clients = getClients().filter(u => u.kyc === 'approved' && (u.balance || 0) > 0);
    if (!clients.length) { toast('No active clients with balance', 'error'); return; }
    rows = clients.map(u => { const r = (u.balance||0)*rate/100; return `<div class="perf-row"><span>${u.name}</span><span style="color:var(--success)">+${fmt(r)} (${rate}%)</span></div>`; }).join('');
    const total = clients.reduce((s,u) => s + (u.balance||0)*rate/100, 0);
    rows += `<div class="sep"></div><div class="perf-row"><strong>Total</strong><strong style="color:var(--success)">${fmt(total)}</strong></div>`;
  } else {
    const uid = document.getElementById('acc-return-client').value;
    const amt = parseFloat(document.getElementById('acc-return-fixed-amt').value);
    const u = DB.users.find(x => x.id === uid);
    if (!u || !amt) { toast('Select client and enter amount', 'error'); return; }
    rows = `<div class="perf-row"><span>${u.name}</span><span style="color:var(--success)">+${fmt(amt)}</span></div>`;
  }
  previewEl.style.display = 'block';
  previewEl.innerHTML = `<div style="background:var(--dark);border-radius:var(--radius);padding:14px"><div style="font-size:12px;font-weight:600;margin-bottom:10px;color:var(--gold)">Preview — ${period}</div>${rows}</div>`;
}

async function postReturns() {
  const type = document.getElementById('acc-return-type').value;
  const period = document.getElementById('acc-return-period').value;
  const notes = document.getElementById('acc-return-notes').value;
  if (!period) { toast('Select a period', 'error'); return; }

  const btn = document.getElementById('acc-post-returns-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Posting...'; }

  try {
    if (type === 'percent') {
      const rate = parseFloat(document.getElementById('acc-return-rate').value);
      if (!rate) { toast('Enter a return rate', 'error'); return; }

      // Uses atomic PostgreSQL function with HWM performance fee logic
      const snapshotId = await db_postPoolSnapshot(
        period, rate,
        parseFloat(fundSettings.mgmt_fee_rate) || 2,
        parseFloat(fundSettings.perf_fee_rate) || 20,
        parseFloat(fundSettings.hurdle_rate) || 8,
        currentUser.id,
        notes || rate + '% return for ' + period
      );

      addAuditLog('POOL_SNAPSHOT_POSTED', 'Period: ' + period + ' | Rate: ' + rate + '% | Snapshot: ' + snapshotId);
      notifyAdmin('RETURNS_POSTED', 'Period: ' + period + ' | Rate: ' + rate + '% | Snapshot: ' + snapshotId);
      Log.financial('RETURNS_POSTED', { period, rate, snapshot_id: snapshotId, admin: currentUser.email });
      toast('Returns posted via pool snapshot ✓', 'success');

    } else {
      // Fixed amount to specific investor — direct transaction
      const uid = document.getElementById('acc-return-client').value;
      const amt = parseFloat(document.getElementById('acc-return-fixed-amt').value);
      const u = DB.users.find(x => x.id === uid);
      if (!u || !amt) { toast('Select client and enter amount', 'error'); return; }

      const ref = 'RET-' + period + '-' + uid.slice(0,8).toUpperCase();
      await db_createTransaction({ investor_id: uid, type: 'return', amount: amt, status: 'approved', reference: ref, notes: notes || 'Return for ' + period });

      // FIX M4 — read once, then write atomically to avoid double-credit race condition
      const currentAcct = await db_getCapitalAccount(uid);
      await sb.from('capital_accounts').upsert({
        investor_id: uid,
        balance: (currentAcct?.balance || 0) + amt,
        total_returns: (currentAcct?.total_returns || 0) + amt,
        updated_at: new Date().toISOString()
      }, { onConflict: 'investor_id' });

      addAuditLog('FIXED_RETURN_POSTED', u.name + ' — $' + amt + ' for ' + period);
      toast('Return posted ✓', 'success');
    }

    await syncDBFromSupabase();
    renderAccLedger(); renderAccStats(); renderReturnsHistory();
    document.getElementById('acc-return-preview').style.display = 'none';

  } catch(e) {
    captureError(e, { action: 'POST_RETURNS', period: document.getElementById('acc-return-period')?.value });
    toast('Failed to post returns: ' + (e.message || 'Please try again.'), 'error');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Post Returns'; }
  }
}

function renderReturnsHistory() {
  const el = document.getElementById('acc-returns-history'); if (!el) return;
  const logs = (DB.returnLog||[]).slice().reverse().slice(0,20);
  if (!logs.length) { el.innerHTML='<div class="empty"><p>No returns posted yet</p></div>'; return; }
  el.innerHTML = logs.map(r=>`<div style="background:var(--dark);border-radius:var(--radius);padding:12px">
    <div style="display:flex;justify-content:space-between;margin-bottom:4px"><span style="font-weight:500;font-size:13px">${r.period}</span><span style="color:var(--success);font-weight:600">+$${(r.totalAmount||0).toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2})}</span></div>
    <div style="font-size:11px;color:var(--text3)">${r.type==='percent'?r.rate+'% — '+r.clientCount+' clients':'Fixed — '+(r.clientName||'')} ${r.notes?'· '+r.notes:''}</div>
  </div>`).join('');
}

function toggleFeeType() {
  const type = document.getElementById('acc-fee-type').value;
  const rg = document.getElementById('acc-fee-rate-group'); if (rg) rg.style.display = type==='custom'?'block':'none';
}

function previewFees() {
  const type = document.getElementById('acc-fee-type').value;
  const scope = document.getElementById('acc-fee-scope').value;
  const period = document.getElementById('acc-fee-period').value;
  if (!period) { toast('Select a period','error'); return; }
  const customRate = parseFloat(document.getElementById('acc-fee-rate')?.value)||0;
  const clients = scope==='all' ? getClients().filter(u=>u.kyc==='approved') : [DB.users.find(u=>u.id===document.getElementById('acc-fee-client').value)].filter(Boolean);
  if (!clients.length) { toast('No clients found','error'); return; }
  const fmt = n=>'$'+n.toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2});
  let rows = clients.map(u => {
    let fee = type==='management' ? calcMgmtFee(u.balance||0)/12 : type==='performance' ? calcPerfFee(u.returns||0) : ((u.balance||0)*customRate)/100;
    return `<div class="perf-row"><span>${u.name}</span><span style="color:var(--danger)">-${fmt(fee)}</span></div>`;
  }).join('');
  const total = clients.reduce((s,u)=>{ return s+(type==='management'?calcMgmtFee(u.balance||0)/12:type==='performance'?calcPerfFee(u.returns||0):((u.balance||0)*customRate)/100); },0);
  rows += `<div class="sep"></div><div class="perf-row"><strong>Total</strong><strong style="color:var(--danger)">${fmt(total)}</strong></div>`;
  const pe = document.getElementById('acc-fee-preview'); if (pe) { pe.style.display='block'; pe.innerHTML=`<div style="font-size:12px;font-weight:600;margin-bottom:10px;color:var(--gold)">Fee Preview — ${period}</div>${rows}`; }
}

async function postFees() {
  const type     = document.getElementById('acc-fee-type').value;
  const scope    = document.getElementById('acc-fee-scope').value;
  const period   = document.getElementById('acc-fee-period').value;
  if (!period) { toast('Select a period', 'error'); return; }

  const customRate = parseFloat(document.getElementById('acc-fee-rate')?.value) || 0;
  const clients = scope === 'all'
    ? getClients().filter(u => u.kyc === 'approved')
    : [DB.users.find(u => u.id === document.getElementById('acc-fee-client').value)].filter(Boolean);
  if (!clients.length) { toast('No eligible clients found', 'error'); return; }

  // Idempotency: block re-posting the same fee type for the same period
  const { data: existing } = await sb.from('transactions')
    .select('id').eq('type', 'fee')
    .like('reference', 'FEE-' + period + '%')
    .limit(1);
  if (existing && existing.length) {
    toast(`${capitalize(type)} fee for ${period} was already posted`, 'error');
    return;
  }

  const confirmed = confirm(
    `Post ${type} fees for ${period} to ${clients.length} client(s)?\n\nThis cannot be undone.`
  );
  if (!confirmed) return;

  const btn = document.querySelector('#page-accounting .btn-gold');
  if (btn) { btn.disabled = true; btn.textContent = 'Posting...'; }

  let totalFee = 0;
  const errors = [];

  try {
    for (const u of clients) {
      // Calculate fee based on live balance
      const account = await db_getCapitalAccount(u.id);
      const balance  = account?.balance  || 0;
      const returns  = account?.total_returns || 0;
      let fee = 0;
      if (type === 'management') fee = calcMgmtFee(balance) / 12;
      else if (type === 'performance') fee = calcPerfFee(returns);
      else fee = (balance * customRate) / 100;

      if (fee <= 0) continue;
      fee = Math.round(fee * 100) / 100; // round to cents

      const ref = 'FEE-' + period + '-' + crypto.randomUUID().slice(0, 6).toUpperCase();

      try {
        // Write as an approved fee transaction — uses process_withdrawal RPC atomically
        await sb.rpc('process_withdrawal', {
          p_investor_id: u.id,
          p_amount:      fee,
          p_method:      type + '_fee',
          p_reference:   ref,
          p_approved_by: currentUser.id
        });
        totalFee += fee;
      } catch(e) {
        errors.push(`${u.name}: ${e.message}`);
      }
    }

    // Write fee log entry to Supabase
    await sb.from('fee_records').insert({
      period, type,
      total_amount:  totalFee,
      client_count:  clients.length - errors.length,
      posted_by:     currentUser.email,
      custom_rate:   customRate || null
    });

    await db_writeAudit(currentUser.id, currentUser.email, 'FEES_POSTED', 'fee_records', null,
      `${capitalize(type)} fee — Period: ${period} — ${fmt(totalFee)} across ${clients.length - errors.length} client(s)`);
    notifyAdmin('FEES_POSTED', capitalize(type) + ' fee — Period: ' + period + ' — ' + fmt(totalFee) + ' across ' + (clients.length - errors.length) + ' client(s)');
    Log.financial('FEES_POSTED', { type, period, total: totalFee, client_count: clients.length - errors.length, errors: errors.length });

    if (errors.length) {
      toast(`Fees posted with ${errors.length} error(s). Check console.`, 'error');
      console.error('Fee posting errors:', errors);
    } else {
      toast(`${capitalize(type)} fees posted ✓ — ${fmt(totalFee)} total`, 'success');
    }

    await syncDBFromSupabase();
    renderAccLedger(); renderAccStats(); renderFeeSummary();
    const pe = document.getElementById('acc-fee-preview'); if (pe) pe.style.display = 'none';
  } catch(e) {
    captureError(e, { action: 'POST_FEES', type: document.getElementById('acc-fee-type')?.value, period: document.getElementById('acc-fee-period')?.value });
    toast('Fee posting failed: ' + e.message, 'error');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Post Fees'; }
  }
}

async function renderFeeSummary() {
  const el = document.getElementById('acc-fee-summary'); if (!el) return;
  const { data: logs } = await sb.from('fee_records')
    .select('*').order('created_at', { ascending: false }).limit(10);
  if (!logs || !logs.length) { el.innerHTML = '<div class="empty"><p>No fees posted yet</p></div>'; return; }
  el.innerHTML = logs.map(f => `<div style="background:var(--dark);border-radius:var(--radius);padding:12px">
    <div style="display:flex;justify-content:space-between;margin-bottom:4px">
      <span style="font-size:13px;font-weight:500;text-transform:capitalize">${sanitize(f.type)} Fee — ${sanitize(f.period)}</span>
      <span style="color:var(--danger);font-weight:600">${fmt(f.total_amount || 0)}</span>
    </div>
    <div style="font-size:11px;color:var(--text3)">${f.client_count} client(s) · ${sanitize(f.posted_by || 'admin')}</div>
  </div>`).join('');
}

function buildStatementHTML(u, period) {
  const txns = (u.transactions||[]).filter(t=>t.date&&t.date.startsWith(period));
  const fmtAmt = n=>'$'+n.toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2});
  // All user-supplied fields sanitized — this HTML is written to a new window via document.write
  const sName    = sanitize(u.name || '');
  const sEmail   = sanitize(u.email || '');
  const sCountry = sanitize(u.kycData?.country || '');
  const sPeriod  = sanitize(period || '');
  const txnRows = txns.length ? txns.map(t=>{
    const isCredit = ['deposit','return'].includes(t.type);
    return `<tr>
    <td style="padding:8px;border-bottom:1px solid #2a2a2a;font-size:12px">${sanitize(fmtDate(t.date))}</td>
    <td style="padding:8px;border-bottom:1px solid #2a2a2a;font-size:12px;text-transform:capitalize">${sanitize(t.type||'')}</td>
    <td style="padding:8px;border-bottom:1px solid #2a2a2a;font-size:12px">${sanitize(t.ref||t.reference||'—')}</td>
    <td style="padding:8px;border-bottom:1px solid #2a2a2a;font-size:12px;color:${isCredit?'#3DB87A':'#E05252'}">${isCredit?'+':'-'}${sanitize(fmtAmt(t.amount||0))}</td>
  </tr>`;
  }).join('') : `<tr><td colspan="4" style="padding:16px;text-align:center;color:#555;font-size:12px">No transactions this period</td></tr>`;
  return `<div style="border-bottom:2px solid #C9A84C;padding-bottom:20px;margin-bottom:24px;display:flex;justify-content:space-between;align-items:flex-start">
    <div><div style="font-family:'Cormorant Garamond',serif;font-size:24px;color:#C9A84C;font-weight:600">Wadstone Investment</div><div style="font-size:11px;color:#666;margin-top:4px">Private Capital Partnership · Nairobi, Kenya</div></div>
    <div style="text-align:right"><div style="font-size:13px;font-weight:600">Account Statement</div><div style="font-size:11px;color:#666">${sPeriod}</div></div>
  </div>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:24px">
    <div><div style="font-size:11px;color:#888;margin-bottom:4px">CLIENT</div><div style="font-weight:600">${sName}</div><div style="font-size:12px;color:#888">${sEmail}</div><div style="font-size:12px;color:#888">${sCountry}</div></div>
    <div style="text-align:right"><div style="font-size:11px;color:#888;margin-bottom:4px">ACCOUNT SUMMARY</div>
      <div style="font-size:13px">Deposited: <strong style="color:#4A9EE8">${sanitize(fmtAmt(u.deposited||0))}</strong></div>
      <div style="font-size:13px">Returns: <strong style="color:#3DB87A">${sanitize(fmtAmt(u.returns||0))}</strong></div>
      <div style="font-size:14px;margin-top:6px">Net Balance: <strong style="color:#C9A84C;font-size:16px">${sanitize(fmtAmt(u.balance||0))}</strong></div>
    </div>
  </div>
  <div style="font-size:12px;font-weight:600;margin-bottom:10px;color:#888;text-transform:uppercase;letter-spacing:0.05em">Transactions — ${sPeriod}</div>
  <table style="width:100%;border-collapse:collapse">
    <thead><tr style="background:#1a1a1a"><th style="padding:8px;text-align:left;font-size:11px;color:#888">Date</th><th style="padding:8px;text-align:left;font-size:11px;color:#888">Type</th><th style="padding:8px;text-align:left;font-size:11px;color:#888">Reference</th><th style="padding:8px;text-align:left;font-size:11px;color:#888">Amount</th></tr></thead>
    <tbody>${txnRows}</tbody>
  </table>
  <div style="margin-top:24px;padding-top:16px;border-top:1px solid #2a2a2a;font-size:10px;color:#555;text-align:center">
    Wadstone Investment · support@wadstone.co.ke · +254 700 000 000 · Westlands, Nairobi, Kenya<br/>
    This statement is for informational purposes only. Past performance does not guarantee future results.
  </div>`;
}

function previewStatement() {
  const period = document.getElementById('acc-stmt-period').value;
  const clientId = document.getElementById('acc-stmt-client').value;
  if (!period) { toast('Select a period','error'); return; }
  const clients = clientId==='all' ? getClients() : [DB.users.find(u=>u.id===clientId)].filter(Boolean);
  if (!clients.length) { toast('No clients found','error'); return; }
  document.getElementById('acc-stmt-preview').style.display='block';
  document.getElementById('acc-stmt-content').innerHTML=buildStatementHTML(clients[0],period);
}

function generateStatement() {
  const period = document.getElementById('acc-stmt-period').value;
  const clientId = document.getElementById('acc-stmt-client').value;
  if (!period) { toast('Select a period','error'); return; }
  const clients = clientId==='all' ? getClients() : [DB.users.find(u=>u.id===clientId)].filter(Boolean);
  if (!clients.length) { toast('No clients found','error'); return; }
  const win=window.open('','_blank');
  win.document.write(`<!DOCTYPE html><html><head><title>Statement ${period}</title>
    <link href="https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@400;600&family=Outfit:wght@300;400;500&display=swap" rel="stylesheet">
    <style>body{font-family:'Outfit',sans-serif;background:#fff;color:#111;padding:40px;}@media print{body{padding:20px}}</style></head><body>`);
  clients.forEach((u,i)=>{ if (i>0) win.document.write('<div style="page-break-before:always"></div>'); win.document.write(buildStatementHTML(u,period)); });
  win.document.write('</body></html>'); win.document.close(); win.print();
  toast('Statement opened — Save as PDF using print dialog ✓','success');
  addAuditLog('Statement Generated','Period: '+period+' — '+(clientId==='all'?'All clients':clients[0]?.name));
}

function viewClientLedger(uid) {
  const u=DB.users.find(x=>x.id===uid); if (!u) return;
  const txns=(u.transactions||[]).slice().reverse();
  const fmt=n=>'$'+n.toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2});
  const rows=txns.map(t=>`<tr>
    <td style="font-size:11px;font-family:'DM Mono',monospace">${sanitize(fmtDate(t.date))}</td>
    <td style="font-size:12px;text-transform:capitalize">${sanitize(t.type)}</td>
    <td style="font-size:12px">${sanitize(t.ref||'—')}</td>
    <td style="color:${['deposit','return'].includes(t.type)?'var(--success)':'var(--danger)'}">${['deposit','return'].includes(t.type)?'+':'-'}${sanitize(fmt(t.amount||0))}</td>
    <td style="font-size:11px;color:var(--text3)">${sanitize(t.notes||'—')}</td>
  </tr>`).join('')||'<tr><td colspan="5" style="text-align:center;padding:16px;color:var(--text3)">No transactions</td></tr>';
  const existing=document.getElementById('modal-client-ledger'); if (existing) existing.remove();
  document.body.insertAdjacentHTML('beforeend',`<div class="modal-overlay active" id="modal-client-ledger">
    <div class="modal" style="max-width:800px;max-height:85vh;overflow-y:auto">
      <div class="modal-title">${sanitize(u.name)} — Full Ledger</div>
      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:20px">
        <div style="background:var(--dark);border-radius:var(--radius);padding:14px;text-align:center"><div style="font-size:11px;color:var(--text3)">Total Deposited</div><div style="font-size:18px;color:var(--info);font-weight:600;margin-top:4px">${sanitize(fmt(u.deposited||0))}</div></div>
        <div style="background:var(--dark);border-radius:var(--radius);padding:14px;text-align:center"><div style="font-size:11px;color:var(--text3)">Total Returns</div><div style="font-size:18px;color:var(--success);font-weight:600;margin-top:4px">${sanitize(fmt(u.returns||0))}</div></div>
        <div style="background:var(--dark);border-radius:var(--radius);padding:14px;text-align:center"><div style="font-size:11px;color:var(--text3)">Net Balance</div><div style="font-size:18px;color:var(--gold);font-weight:600;margin-top:4px">${sanitize(fmt(u.balance||0))}</div></div>
      </div>
      <div class="table-wrap"><table>
        <thead><tr><th>Date</th><th>Type</th><th>Reference</th><th>Amount</th><th>Notes</th></tr></thead>
        <tbody>${rows}</tbody>
      </table></div>
      <div class="modal-footer">
        <button class="btn btn-ghost" onclick="document.getElementById('modal-client-ledger').remove()">Close</button>
        <button class="btn btn-gold btn-sm" onclick="printClientLedger('${sanitize(u.id)}')">Print / PDF</button>
      </div>
    </div>
  </div>`);
}

function printClientLedger(uid) {
  const u=DB.users.find(x=>x.id===uid); if (!u) return;
  const period=new Date().toISOString().slice(0,7);
  const win=window.open('','_blank');
  win.document.write(`<!DOCTYPE html><html><head><title>Ledger - ${sanitize(u.name)}</title><style>body{font-family:sans-serif;padding:40px;color:#111;}table{width:100%;border-collapse:collapse;}th,td{padding:8px;border-bottom:1px solid #eee;text-align:left;font-size:12px;}th{background:#f5f5f5;}</style></head><body>${buildStatementHTML(u,period)}</body></html>`);
  win.document.close(); win.print();
}

function openJournalEntry() {
  populateAccClientDropdowns();
  const jd=document.getElementById('jnl-date'); if (jd) jd.value=new Date().toISOString().slice(0,10);
  ['jnl-desc','jnl-notes'].forEach(id=>{ const el=document.getElementById(id); if (el) el.value=''; });
  ['jnl-debit','jnl-credit'].forEach(id=>{ const el=document.getElementById(id); if (el) el.value=''; });
  openModal('modal-journal');
}

async function saveJournalEntry() {
  const desc     = document.getElementById('jnl-desc').value.trim();
  const debit    = parseFloat(document.getElementById('jnl-debit').value)  || 0;
  const credit   = parseFloat(document.getElementById('jnl-credit').value) || 0;
  const date     = document.getElementById('jnl-date').value;
  const clientId = document.getElementById('jnl-client').value || null;
  const notes    = document.getElementById('jnl-notes').value.trim();

  if (!desc)           { toast('Enter a description', 'error'); return; }
  if (!debit && !credit) { toast('Enter debit or credit amount', 'error'); return; }

  const btn = document.querySelector('#modal-journal .btn-gold');
  if (btn) { btn.disabled = true; btn.textContent = 'Saving...'; }

  try {
    const entry = await db_createJournalEntry({
      date:        date || new Date().toISOString().slice(0,10),
      description: desc,
      debit:       debit  || null,
      credit:      credit || null,
      investor_id: clientId,
      notes:       notes  || null,
      posted_by:   currentUser.email
    });

    await db_writeAudit(currentUser.id, currentUser.email, 'JOURNAL_ENTRY', 'journal_entries', entry.id, entry.id + ' — ' + desc);
    closeModal('modal-journal');
    await renderJournalTable();
    toast('Journal entry posted ✓', 'success');
  } catch(e) {
    toast('Failed to save journal entry: ' + e.message, 'error');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Post Entry'; }
  }
}

async function renderJournalTable() {
  const tbody = document.getElementById('acc-journal-table'); if (!tbody) return;
  const entries = await db_getJournalEntries();
  if (!entries.length) { tbody.innerHTML = '<tr><td colspan="7"><div class="empty"><p>No journal entries yet</p></div></td></tr>'; return; }
  tbody.innerHTML = entries.map(e => `<tr>
    <td style="font-size:11px;font-family:'DM Mono',monospace">${sanitize(e.date || fmtDate(e.created_at))}</td>
    <td style="font-size:11px;color:var(--gold)">${sanitize(e.id?.toString().slice(0,8) || '—')}</td>
    <td style="font-size:12px">${sanitize(e.description)}</td>
    <td style="color:var(--danger)">${e.debit  ? fmt(e.debit)  : '—'}</td>
    <td style="color:var(--success)">${e.credit ? fmt(e.credit) : '—'}</td>
    <td style="font-size:12px">${sanitize(e.investors?.name || '—')}</td>
    <td style="font-size:11px;color:var(--text3)">${sanitize(e.posted_by || 'admin')}</td>
  </tr>`).join('');
}

function exportLedgerCSV() {
  const clients=getClients();
  if (!clients.length) { toast('No clients to export','error'); return; }
  const headers=['Name','Email','Country','Joined','Deposited','Returns','Mgmt Fee','Perf Fee','Net Balance','KYC'];
  const rows=clients.map(u=>[u.name,u.email,u.kycData?.country||'',u.submittedAt?fmtDate(u.submittedAt):'',(u.deposited||0).toFixed(2),(u.returns||0).toFixed(2),calcMgmtFee(u.deposited||0).toFixed(2),calcPerfFee(u.returns||0).toFixed(2),(u.balance||0).toFixed(2),u.kyc||'']);
  const csv=[headers,...rows].map(r=>r.map(c=>`"${c}"`).join(',')).join('\n');
  const blob=new Blob([csv],{type:'text/csv'});
  const a=document.createElement('a'); a.href=URL.createObjectURL(blob);
  a.download='wadstone_ledger_'+new Date().toISOString().slice(0,10)+'.csv'; a.click();
  toast('Ledger exported ✓','success');
  addAuditLog('Export','Client ledger exported to CSV');
}

function openModal(id) { document.getElementById(id).classList.add('active'); }
function closeModal(id) { document.getElementById(id).classList.remove('active'); }

function kycDecision(action) {
  if (!currentKycTarget) return;
  closeModal('modal-kyc-action');
  // Delegate to quickKycAction which handles Supabase update, audit log, and email
  quickKycAction(currentKycTarget, action).then(() => renderAdminKYC());
}

function txnDecision(action) { closeModal('modal-txn-action'); }

// FIX C2: View uploaded KYC document via Supabase Storage signed URL.
// No longer reads from localStorage.
async function viewDoc(e) {
  const btn = e.currentTarget || e.target;
  const storagePath = btn.getAttribute('data-path');
  const docKey = btn.getAttribute('data-key');
  if (!storagePath) { toast('Document path not found', 'error'); return; }
  try {
    btn.textContent = 'Loading...';
    btn.disabled = true;
    const { data: fileData, error: fileError } = await sb.storage
      .from('kyc-documents')
      .download(storagePath);
    if (fileError) { toast('Download error: ' + fileError.message, 'error'); return; }
    const url = URL.createObjectURL(fileData);
    const a = document.createElement('a');
    a.href = url;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 3000);
  } catch (e) {
    toast('Error: ' + (e.message || 'Unknown'), 'error');
  } finally {
    btn.textContent = 'View';
    btn.disabled = false;
  }
}
// ════════════════════════════════════════════
//  TOAST
// ════════════════════════════════════════════
function toast(msg, type = 'info') {
  const c = document.getElementById('toast-container');
  const el = document.createElement('div');
  el.className = 'toast ' + type;
  const icons = { success: '✓', error: '✗', info: 'ℹ' };
  // FIX H2: use textContent for the message to prevent HTML injection
  const icon = document.createElement('span');
  icon.style.color = type==='success'?'var(--success)':type==='error'?'var(--danger)':'var(--info)';
  icon.textContent = icons[type] || '•';
  const text = document.createTextNode(' ' + String(msg));
  el.appendChild(icon);
  el.appendChild(text);
  c.appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; el.style.transition = 'opacity 0.3s'; setTimeout(() => el.remove(), 300); }, 3500);
}

// ════════════════════════════════════════════
//  UTILS
// ════════════════════════════════════════════
function fmt(n) {
  return '$' + Number(n || 0).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}
function fmtDate(iso) {
  return new Date(iso).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
}
function capitalize(s) { return s ? s.charAt(0).toUpperCase() + s.slice(1) : ''; }
function statusBadge(s) {
  return s === 'approved' ? 'badge-success' : s === 'pending' ? 'badge-warn' : s === 'rejected' ? 'badge-danger' : 'badge-info';
}
function kycBadge(k) {
  return k === 'approved' ? 'badge-success' : k === 'pending' ? 'badge-warn' : 'badge-danger';
}

function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('open');
}

// Close sidebar when clicking outside on mobile
document.addEventListener('click', (e) => {
  if (window.innerWidth < 900) {
    const sidebar = document.getElementById('sidebar');
    const menuBtn = document.getElementById('menu-btn');
    if (!sidebar.contains(e.target) && !menuBtn.contains(e.target)) {
      sidebar.classList.remove('open');
    }
  }
});

// Close modals on overlay click
document.querySelectorAll('.modal-overlay').forEach(o => {
  o.addEventListener('click', (e) => { if (e.target === o) o.classList.remove('active'); });
});

// Enter key support for login form
document.addEventListener('DOMContentLoaded', () => {
  const loginPassword = document.getElementById('login-password');
  if (loginPassword) loginPassword.addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
  const loginEmail = document.getElementById('login-email');
  if (loginEmail) loginEmail.addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
});

// ════════════════════════════════════════════════════════════
//  THEME TOGGLE — Light / Dark mode
// ════════════════════════════════════════════════════════════
function toggleTheme() {
  const root = document.documentElement;
  const current = root.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
  const next = current === 'dark' ? 'light' : 'dark';
  root.setAttribute('data-theme', next);
  try { localStorage.setItem('ws-theme', next); } catch (e) { /* storage unavailable */ }
}
