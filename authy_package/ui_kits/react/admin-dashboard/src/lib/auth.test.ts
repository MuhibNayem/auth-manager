import { describe, expect, it } from 'vitest';
import {
  ADMIN_TOKEN_KEY,
  decodeJwtPayload,
  getTokenExpiry,
  isTokenValid,
} from './auth';

/** Build an unsigned JWT (alg none) with the given payload. */
function makeJwt(payload: Record<string, unknown>): string {
  const b64url = (obj: unknown) =>
    btoa(JSON.stringify(obj))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  return `${b64url({ alg: 'none', typ: 'JWT' })}.${b64url(payload)}.signature`;
}

describe('admin token helpers', () => {
  it('uses the canonical authy_admin_token storage key', () => {
    expect(ADMIN_TOKEN_KEY).toBe('authy_admin_token');
  });

  it('decodes a well-formed JWT payload', () => {
    const token = makeJwt({ sub: 'admin-1', type: 'access', exp: 2000000000 });
    expect(decodeJwtPayload(token)).toMatchObject({ sub: 'admin-1', type: 'access' });
  });

  it('returns null for structurally invalid tokens', () => {
    expect(decodeJwtPayload('not-a-jwt')).toBeNull();
    expect(decodeJwtPayload('a.b')).toBeNull();
    expect(decodeJwtPayload('a.%%%!.c')).toBeNull();
  });

  it('extracts the exp claim when present', () => {
    const token = makeJwt({ exp: 2100000000 });
    expect(getTokenExpiry(token)).toBe(2100000000);
  });

  it('returns null expiry for missing/invalid exp', () => {
    expect(getTokenExpiry(makeJwt({ sub: 'x' }))).toBeNull();
    expect(getTokenExpiry(null)).toBeNull();
    expect(getTokenExpiry('garbage')).toBeNull();
  });

  it('treats tokens with future exp as valid and past exp as invalid', () => {
    const now = 1_000_000;
    expect(isTokenValid(makeJwt({ exp: now + 3600 }), now)).toBe(true);
    expect(isTokenValid(makeJwt({ exp: now - 1 }), now)).toBe(false);
    // Within the 5s skew window the token is already considered expired.
    expect(isTokenValid(makeJwt({ exp: now + 3 }), now)).toBe(false);
  });

  it('rejects null/empty tokens', () => {
    expect(isTokenValid(null)).toBe(false);
    expect(isTokenValid('')).toBe(false);
  });

  it('accepts tokens without an exp claim on presence alone', () => {
    // Backend remains the authority; client only enforces exp when present.
    expect(isTokenValid(makeJwt({ sub: 'opaque' }))).toBe(true);
  });
});
