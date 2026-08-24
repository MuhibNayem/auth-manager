/**
 * Client-side admin session helpers.
 *
 * The dashboard stores the admin access token (a JWT issued by
 * `POST /admin/api/v1/auth/login`) under `tessera_admin_token` in
 * localStorage. Signature verification is the backend's job; here we only
 * decode the payload to enforce token expiry on the client.
 */

export const ADMIN_TOKEN_KEY = 'tessera_admin_token';

/** Seconds before real expiry at which a token is already treated as expired. */
const EXPIRY_SKEW_SECONDS = 5;

/**
 * Decode a JWT payload without verifying the signature.
 * Returns null when the token is not a structurally valid JWT.
 */
export function decodeJwtPayload(token: string): Record<string, unknown> | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');
    if (typeof atob !== 'function') return null;
    const json = atob(padded);
    const payload: unknown = JSON.parse(json);
    return payload !== null && typeof payload === 'object'
      ? (payload as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

/**
 * Extract the `exp` claim (epoch seconds) from a JWT.
 * Returns null when the token is malformed or carries no numeric `exp`.
 */
export function getTokenExpiry(token: string | null): number | null {
  if (!token) return null;
  const payload = decodeJwtPayload(token);
  if (!payload || typeof payload.exp !== 'number' || !Number.isFinite(payload.exp)) {
    return null;
  }
  return payload.exp;
}

/**
 * True when the token exists and, if it carries an `exp` claim, that claim
 * is still in the future (minus a small skew). Tokens without an `exp`
 * claim pass the presence check; the backend remains the authority on
 * their validity.
 */
export function isTokenValid(
  token: string | null,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): boolean {
  if (!token) return false;
  const exp = getTokenExpiry(token);
  if (exp === null) return true;
  return exp - EXPIRY_SKEW_SECONDS > nowSeconds;
}

function storageAvailable(): boolean {
  try {
    return typeof window !== 'undefined' && !!window.localStorage;
  } catch {
    return false;
  }
}

/** Read the persisted admin token, if any. */
export function readStoredToken(): string | null {
  if (!storageAvailable()) return null;
  try {
    return window.localStorage.getItem(ADMIN_TOKEN_KEY);
  } catch {
    return null;
  }
}

/** Persist the admin token. */
export function storeToken(token: string): void {
  if (!storageAvailable()) return;
  try {
    window.localStorage.setItem(ADMIN_TOKEN_KEY, token);
  } catch {
    // Storage may be unavailable (private mode / quota); the in-memory
    // session still works for the current page load.
  }
}

/** Remove the persisted admin token. */
export function clearStoredToken(): void {
  if (!storageAvailable()) return;
  try {
    window.localStorage.removeItem(ADMIN_TOKEN_KEY);
  } catch {
    // Ignore storage errors on teardown.
  }
}
