import { describe, expect, it } from 'vitest';

import {
  DenyHostError,
  denyHostsFetch,
  type DenyHostsFetchOptions,
  type HttpCall,
  UnsupportedMethodError,
  UnsupportedProtocolError,
} from './deny-hosts';

const TEST_DENY = ['cardanowall.com', '*.cardanowall.com', 'localhost', '127.0.0.1'] as const;

function okFetch(body: string, status = 200): typeof fetch {
  return async () =>
    new Response(body, {
      status,
      headers: { 'content-type': 'text/plain' },
    });
}

function baseOpts(extra: Partial<DenyHostsFetchOptions> = {}): DenyHostsFetchOptions {
  const audit: HttpCall[] = [];
  return {
    denyHosts: [...TEST_DENY],
    audit,
    purpose: 'https',
    fetchImpl: okFetch('ok'),
    ...extra,
  };
}

describe('denyHostsFetch', () => {
  it('records a successful fetch to an allowed host', async () => {
    const opts = baseOpts({ fetchImpl: okFetch('ok-body') });
    const response = await denyHostsFetch('https://example.com/path', undefined, opts);
    expect(response.status).toBe(200);
    expect(opts.audit).toHaveLength(1);
    const entry = opts.audit[0];
    expect(entry?.url).toBe('https://example.com/path');
    expect(entry?.method).toBe('GET');
    expect(entry?.status).toBe(200);
    expect(entry?.bytes).toBe('ok-body'.length);
    expect(entry?.purpose).toBe('https');
    expect(entry?.duration_ms).toBeGreaterThanOrEqual(0);
  });

  it('fails synchronously with DenyHostError on exact-match denied host and records audit row', async () => {
    const opts = baseOpts();
    await expect(
      denyHostsFetch('https://cardanowall.com/anything', undefined, opts),
    ).rejects.toBeInstanceOf(DenyHostError);
    // The deny path records an audit row before throwing, so the rejected
    // attempt is still visible in the audit trail.
    expect(opts.audit).toHaveLength(1);
    expect(opts.audit[0]?.status).toBe(0);
    expect(opts.audit[0]?.duration_ms).toBe(0);
  });

  it('attaches host, url, and SERVICE_INDEPENDENCE_VIOLATION code to DenyHostError', async () => {
    const opts = baseOpts();
    try {
      await denyHostsFetch('https://cardanowall.com/secret', undefined, opts);
      throw new Error('expected denyHostsFetch to throw');
    } catch (e) {
      expect(e).toBeInstanceOf(DenyHostError);
      const err = e as DenyHostError;
      expect(err.code).toBe('SERVICE_INDEPENDENCE_VIOLATION');
      expect(err.host).toBe('cardanowall.com');
      expect(err.url).toBe('https://cardanowall.com/secret');
    }
  });

  it('matches wildcard subdomain entries (single label) and pins host to actual hostname', async () => {
    const opts = baseOpts();
    try {
      await denyHostsFetch('https://api.cardanowall.com/v1', undefined, opts);
      throw new Error('expected denyHostsFetch to throw');
    } catch (e) {
      expect(e).toBeInstanceOf(DenyHostError);
      const err = e as DenyHostError;
      expect(err.host).toBe('api.cardanowall.com');
      expect(err.code).toBe('SERVICE_INDEPENDENCE_VIOLATION');
    }
    expect(opts.audit).toHaveLength(1);
    expect(opts.audit[0]?.status).toBe(0);
  });

  it('matches wildcard subdomain entries (multi-label depth) and pins host to actual hostname', async () => {
    const opts = baseOpts();
    try {
      await denyHostsFetch('https://nested.api.cardanowall.com/x', undefined, opts);
      throw new Error('expected denyHostsFetch to throw');
    } catch (e) {
      expect(e).toBeInstanceOf(DenyHostError);
      const err = e as DenyHostError;
      expect(err.host).toBe('nested.api.cardanowall.com');
      expect(err.code).toBe('SERVICE_INDEPENDENCE_VIOLATION');
    }
    expect(opts.audit).toHaveLength(1);
    expect(opts.audit[0]?.status).toBe(0);
  });

  it('denies localhost and 127.0.0.1 to forbid loopback indirection', async () => {
    const optsLocalhost = baseOpts();
    await expect(
      denyHostsFetch('http://localhost:8080/anything', undefined, optsLocalhost),
    ).rejects.toBeInstanceOf(DenyHostError);

    const optsIp = baseOpts();
    await expect(
      denyHostsFetch('http://127.0.0.1:3000/secret', undefined, optsIp),
    ).rejects.toBeInstanceOf(DenyHostError);
  });

  it('allows any host when denyHosts is empty', async () => {
    const opts = baseOpts({ denyHosts: [], fetchImpl: okFetch('whatever') });
    const response = await denyHostsFetch('https://cardanowall.com/should-pass', undefined, opts);
    expect(response.status).toBe(200);
    expect(opts.audit).toHaveLength(1);
    expect(opts.audit[0]?.url).toBe('https://cardanowall.com/should-pass');
  });

  it('propagates POST method and respects purpose tag', async () => {
    const opts = baseOpts({ fetchImpl: okFetch('posted'), purpose: 'cardano' });
    const response = await denyHostsFetch(
      'https://koios.rest/api/v1/blocks',
      { method: 'POST', body: '{}' },
      opts,
    );
    expect(response.status).toBe(200);
    expect(opts.audit).toHaveLength(1);
    expect(opts.audit[0]?.method).toBe('POST');
    expect(opts.audit[0]?.purpose).toBe('cardano');
  });

  // --- error, unsupported-protocol, and unsupported-method paths ---

  it('errored fetch records an audit row before re-throwing', async () => {
    const original = new Error('network down');
    const audit: HttpCall[] = [];
    const opts: DenyHostsFetchOptions = {
      denyHosts: [],
      audit,
      purpose: 'https',
      fetchImpl: async () => {
        throw original;
      },
    };
    await expect(denyHostsFetch('https://example.com/x', undefined, opts)).rejects.toBe(original);
    expect(audit).toHaveLength(1);
    expect(audit[0]?.status).toBe(0);
    expect(audit[0]?.bytes).toBe(0);
    expect(audit[0]?.duration_ms).toBeGreaterThanOrEqual(0);
  });

  it('rejects data: URL with UnsupportedProtocolError + audit row', async () => {
    const opts = baseOpts();
    await expect(
      denyHostsFetch('data:text/plain;base64,SGVsbG8=', undefined, opts),
    ).rejects.toBeInstanceOf(UnsupportedProtocolError);
    expect(opts.audit).toHaveLength(1);
    expect(opts.audit[0]?.status).toBe(0);
  });

  it('rejects file: URL with UnsupportedProtocolError', async () => {
    const opts = baseOpts();
    await expect(denyHostsFetch('file:///etc/passwd', undefined, opts)).rejects.toBeInstanceOf(
      UnsupportedProtocolError,
    );
  });

  it('rejects PUT method with UnsupportedMethodError', async () => {
    const opts = baseOpts();
    await expect(
      denyHostsFetch('https://example.com/x', { method: 'PUT' }, opts),
    ).rejects.toBeInstanceOf(UnsupportedMethodError);
    expect(opts.audit).toHaveLength(1);
  });

  it('blocks IPv6 [::1] when localhost in deny-list', async () => {
    const opts = baseOpts();
    await expect(denyHostsFetch('http://[::1]/x', undefined, opts)).rejects.toBeInstanceOf(
      DenyHostError,
    );
  });

  it('blocks 127.1.2.3 (full /8 block) when 127.0.0.1 in deny-list', async () => {
    const opts = baseOpts();
    await expect(denyHostsFetch('http://127.1.2.3/x', undefined, opts)).rejects.toBeInstanceOf(
      DenyHostError,
    );
  });

  it('blocks cloud-metadata 169.254.169.254 when localhost in deny-list', async () => {
    const opts = baseOpts();
    await expect(
      denyHostsFetch('http://169.254.169.254/latest/meta-data', undefined, opts),
    ).rejects.toBeInstanceOf(DenyHostError);
  });

  it('does NOT block 8.8.8.8 (control)', async () => {
    const opts = baseOpts({ fetchImpl: okFetch('reachable') });
    const r = await denyHostsFetch('http://8.8.8.8/', undefined, opts);
    expect(r.status).toBe(200);
    expect(opts.audit).toHaveLength(1);
  });
});
