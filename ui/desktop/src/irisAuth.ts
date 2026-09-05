/**
 * Iris staff sign-in for the Optispan Assistant (distro item #3-final).
 *
 * The Iris built-in reads the staff Firebase ID token from IRIS_STAFF_TOKEN_FILE
 * on every call. This module owns that token's lifecycle, entirely in the main
 * process:
 *
 *   - Sign-in sends email+password DIRECTLY to Google Identity Toolkit (never to
 *     our gateway), and gets back a short-lived ID token + a long-lived refresh
 *     token.
 *   - The refresh token (the sensitive secret) is encrypted with the OS keychain
 *     (Electron safeStorage) and stored under userData; it never touches disk in
 *     the clear and never leaves the machine.
 *   - The ID token (~1h) is written to IRIS_STAFF_TOKEN_FILE and refreshed a few
 *     minutes before expiry, so goosed always reads a live token without a
 *     restart.
 *   - Sign-out clears both.
 *
 * The gateway + Apollo do the authority: they verify this ID token, enforce the
 * staff role, and audit per user. Nothing here grants access on its own.
 */
import { app, safeStorage } from 'electron';
import fs from 'fs';
import path from 'path';

// Public Iris Firebase web config (shipped in the Iris client bundle).
// Env override lets a different environment (e.g. staging) point elsewhere.
const FIREBASE_API_KEY =
  process.env.IRIS_FIREBASE_API_KEY || 'AIzaSyCoVE7ryRJh27jLBtG08lT75YBuw3IIirM';

const IDENTITY_TOOLKIT = 'https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword';
const SECURE_TOKEN = 'https://securetoken.googleapis.com/v1/token';

const REFRESH_SKEW_SECONDS = 300; // refresh 5 min before expiry

function tokenFilePath(): string {
  return (
    process.env.IRIS_STAFF_TOKEN_FILE ||
    path.join(app.getPath('appData'), 'Block', 'goose', 'config', 'iris_staff_token')
  );
}

function refreshStorePath(): string {
  // Co-located with the ID-token file (same Block/goose/config dir) so all Iris
  // auth state lives together and is independent of the Electron productName —
  // app.getPath('userData') is derived from productName, so a rename would
  // otherwise orphan this file.
  return path.join(app.getPath('appData'), 'Block', 'goose', 'config', 'iris_refresh_token.enc');
}

// Previous location (Electron userData); read once for one-time migration.
function legacyRefreshStorePath(): string {
  return path.join(app.getPath('userData'), 'iris_refresh_token.enc');
}

interface AuthState {
  email: string | null;
  refreshToken: string | null;
}

const state: AuthState = { email: null, refreshToken: null };
let refreshTimer: ReturnType<typeof setTimeout> | null = null;

const RETRY_SECONDS = 60; // after a transient refresh failure, try again soon

// Called when the session can no longer produce a valid token and the user must
// sign in again (refresh token rejected, or none available). main.ts wires this
// to open the login window — the reliable way back in when a token dies.
let onReauthNeeded: (() => void) | null = null;
export function setOnReauthNeeded(cb: () => void): void {
  onReauthNeeded = cb;
}
function requestReauth(): void {
  try {
    onReauthNeeded?.();
  } catch (e) {
    console.error('[irisAuth] reauth handler error:', e);
  }
}
function scheduleRetry(): void {
  if (refreshTimer) clearTimeout(refreshTimer);
  refreshTimer = setTimeout(() => {
    void refreshNow();
  }, RETRY_SECONDS * 1000);
}

function writeTokenFile(idToken: string): void {
  const p = tokenFilePath();
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, idToken, { encoding: 'utf8', mode: 0o600 });
}

function deleteTokenFile(): void {
  try {
    fs.rmSync(tokenFilePath(), { force: true });
  } catch {
    // best-effort
  }
}

function persistRefreshToken(refreshToken: string, email: string): void {
  if (!safeStorage.isEncryptionAvailable()) {
    // No OS keychain — refuse to persist the refresh token in the clear.
    // The current session still works; the user re-signs in next launch.
    return;
  }
  const blob = safeStorage.encryptString(JSON.stringify({ refreshToken, email }));
  fs.mkdirSync(path.dirname(refreshStorePath()), { recursive: true });
  fs.writeFileSync(refreshStorePath(), blob, { mode: 0o600 });
}

function loadPersistedRefreshToken(): { refreshToken: string; email: string } | null {
  try {
    if (!safeStorage.isEncryptionAvailable()) return null;
    let p = refreshStorePath();
    if (!fs.existsSync(p) && fs.existsSync(legacyRefreshStorePath())) {
      p = legacyRefreshStorePath(); // one-time read from the old userData location
    }
    const blob = fs.readFileSync(p);
    const parsed = JSON.parse(safeStorage.decryptString(blob));
    if (parsed?.refreshToken) return parsed;
  } catch {
    // no stored token / unreadable
  }
  return null;
}

function clearPersistedRefreshToken(): void {
  // Remove both the current and legacy locations so sign-out fully clears state.
  for (const p of [refreshStorePath(), legacyRefreshStorePath()]) {
    try {
      fs.rmSync(p, { force: true });
    } catch {
      // best-effort
    }
  }
}

function scheduleRefresh(expiresInSeconds: number): void {
  if (refreshTimer) clearTimeout(refreshTimer);
  const delayMs = Math.max(30, expiresInSeconds - REFRESH_SKEW_SECONDS) * 1000;
  refreshTimer = setTimeout(() => {
    void refreshNow();
  }, delayMs);
}

/** Exchange email+password with Google Identity Toolkit (direct, never via our gateway). */
export async function signIn(email: string, password: string): Promise<{ email: string }> {
  const resp = await fetch(`${IDENTITY_TOOLKIT}?key=${FIREBASE_API_KEY}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password, returnSecureToken: true }),
  });
  const data = await resp.json();
  if (!resp.ok) {
    const code = data?.error?.message || `HTTP ${resp.status}`;
    throw new Error(`Sign-in failed: ${code}`);
  }
  writeTokenFile(data.idToken);
  state.email = data.email || email;
  state.refreshToken = data.refreshToken;
  persistRefreshToken(data.refreshToken, state.email!);
  scheduleRefresh(Number(data.expiresIn) || 3600);
  return { email: state.email! };
}

/** Refresh the ID token from the stored refresh token; rewrites the token file.
 *  On a hard failure (refresh token rejected) it clears the session and asks for
 *  re-auth; on a transient failure it schedules a short retry — either way the
 *  session never silently rots into an unusable-but-"signed in" state. */
export async function refreshNow(): Promise<boolean> {
  const persisted = loadPersistedRefreshToken();
  const rt = state.refreshToken || persisted?.refreshToken || null;
  const email = state.email || persisted?.email || null;
  if (!rt) {
    requestReauth();
    return false;
  }
  try {
    const resp = await fetch(`${SECURE_TOKEN}?key=${FIREBASE_API_KEY}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `grant_type=refresh_token&refresh_token=${encodeURIComponent(rt)}`,
    });
    const data = await resp.json();
    if (!resp.ok) {
      const code = data?.error?.message || `HTTP ${resp.status}`;
      if (resp.status === 400 || resp.status === 401 || resp.status === 403) {
        // Refresh token revoked/expired — the session is over. Clear and re-prompt.
        console.error('[irisAuth] refresh token rejected, re-auth needed:', code);
        signOut();
        requestReauth();
        return false;
      }
      // Transient (5xx/network-ish) — keep the session, retry shortly.
      throw new Error(`Token refresh failed: ${code}`);
    }
    writeTokenFile(data.id_token);
    state.email = email;
    state.refreshToken = data.refresh_token || rt; // Google rotates the refresh token
    persistRefreshToken(state.refreshToken!, email || '');
    scheduleRefresh(Number(data.expires_in) || 3600);
    console.info('[irisAuth] ID token refreshed');
    return true;
  } catch (err) {
    // Transient failure: do NOT give up — retry soon so a blip self-heals.
    console.error(`[irisAuth] refresh error (retrying in ${RETRY_SECONDS}s):`, err);
    scheduleRetry();
    return false;
  }
}

/** Clear the session: cancel refresh, wipe the ID token file and the stored refresh token. */
export function signOut(): void {
  if (refreshTimer) {
    clearTimeout(refreshTimer);
    refreshTimer = null;
  }
  state.email = null;
  state.refreshToken = null;
  deleteTokenFile();
  clearPersistedRefreshToken();
}

/** On app start: if a refresh token is stored, mint a fresh ID token file. If
 *  that fails (can't produce a usable token), ask for re-auth rather than
 *  leaving a dead session that still looks "signed in". */
export async function initOnStartup(): Promise<void> {
  const stored = loadPersistedRefreshToken();
  if (!stored) return; // no session — main.ts opens login via !signedIn
  state.email = stored.email;
  state.refreshToken = stored.refreshToken;
  const ok = await refreshNow();
  if (!ok) requestReauth();
}

/** True only when we currently hold a usable (non-expired) ID token file. */
export function hasValidToken(): boolean {
  try {
    const raw = fs.readFileSync(tokenFilePath(), 'utf8').trim();
    if (!raw) return false;
    const payload = JSON.parse(Buffer.from(raw.split('.')[1] + '==', 'base64').toString('utf8'));
    return typeof payload.exp === 'number' && payload.exp * 1000 > Date.now() + 30_000;
  } catch {
    return false;
  }
}

export function status(): { signedIn: boolean; email: string | null } {
  const stored = state.refreshToken ? state : loadPersistedRefreshToken();
  return { signedIn: !!stored?.refreshToken, email: state.email || (stored as AuthState)?.email || null };
}
