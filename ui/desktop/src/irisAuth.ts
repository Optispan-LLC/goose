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
  return path.join(app.getPath('userData'), 'iris_refresh_token.enc');
}

interface AuthState {
  email: string | null;
  refreshToken: string | null;
}

const state: AuthState = { email: null, refreshToken: null };
let refreshTimer: ReturnType<typeof setTimeout> | null = null;

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
  fs.writeFileSync(refreshStorePath(), blob, { mode: 0o600 });
}

function loadPersistedRefreshToken(): { refreshToken: string; email: string } | null {
  try {
    if (!safeStorage.isEncryptionAvailable()) return null;
    const blob = fs.readFileSync(refreshStorePath());
    const parsed = JSON.parse(safeStorage.decryptString(blob));
    if (parsed?.refreshToken) return parsed;
  } catch {
    // no stored token / unreadable
  }
  return null;
}

function clearPersistedRefreshToken(): void {
  try {
    fs.rmSync(refreshStorePath(), { force: true });
  } catch {
    // best-effort
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

/** Refresh the ID token from the stored refresh token; rewrites the token file. */
export async function refreshNow(): Promise<boolean> {
  const rt = state.refreshToken || loadPersistedRefreshToken()?.refreshToken || null;
  const email = state.email || loadPersistedRefreshToken()?.email || null;
  if (!rt) return false;
  try {
    const resp = await fetch(`${SECURE_TOKEN}?key=${FIREBASE_API_KEY}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `grant_type=refresh_token&refresh_token=${encodeURIComponent(rt)}`,
    });
    const data = await resp.json();
    if (!resp.ok) {
      // A hard failure (revoked/expired refresh token) means the session is over.
      const code = data?.error?.message || `HTTP ${resp.status}`;
      if (resp.status === 400 || resp.status === 401 || resp.status === 403) {
        signOut();
      }
      throw new Error(`Token refresh failed: ${code}`);
    }
    writeTokenFile(data.id_token);
    state.email = email;
    state.refreshToken = data.refresh_token || rt; // Google rotates the refresh token
    persistRefreshToken(state.refreshToken!, email || '');
    scheduleRefresh(Number(data.expires_in) || 3600);
    return true;
  } catch (err) {
    // Leave any existing token file in place until it naturally expires.
    console.error('[irisAuth] refresh error:', err);
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

/** On app start: if a refresh token is stored, mint a fresh ID token file immediately. */
export async function initOnStartup(): Promise<void> {
  const stored = loadPersistedRefreshToken();
  if (!stored) return;
  state.email = stored.email;
  state.refreshToken = stored.refreshToken;
  await refreshNow();
}

export function status(): { signedIn: boolean; email: string | null } {
  const stored = state.refreshToken ? state : loadPersistedRefreshToken();
  return { signedIn: !!stored?.refreshToken, email: state.email || (stored as AuthState)?.email || null };
}
