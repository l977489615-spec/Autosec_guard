// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fetchWithEngineRecovery, submitAuth, testCurrentAiConfig, updateCurrentProfile } from './api';

describe('cookie session API contract', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('never sends the browser session sentinel as a Bearer token', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ user: { username: 'admin' } }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }));
    vi.stubGlobal('fetch', fetchMock);

    await updateCurrentProfile('cookie-session', { new_password: 'updated-password' });
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(new Headers(init.headers).has('Authorization')).toBe(false);
    expect(init.credentials).toBe('same-origin');
  });

  it('uses the same cookie-safe path for AI tests', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ success: true, model: 'fast-model' }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }));
    vi.stubGlobal('fetch', fetchMock);

    await testCurrentAiConfig('cookie-session', { base_url: 'https://example.com/v1' });
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(new Headers(init.headers).has('Authorization')).toBe(false);
    expect(init.credentials).toBe('same-origin');
  });

  it('surfaces the v3 nested error message and trace id on login', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({
      error: { code: 'ORIGIN_REJECTED', message: '请求来源未授权。' },
      trace_id: 'trace-login-1',
    }), { status: 403, headers: { 'Content-Type': 'application/json' } })));

    await expect(submitAuth('login', { username: 'admin', password: 'invalid-password' }))
      .rejects.toMatchObject({ message: '请求来源未授权。', traceId: 'trace-login-1' });
  });

  it('replays an idempotent request after a temporary engine disconnect', async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn()
      .mockRejectedValueOnce(new TypeError('Failed to fetch'))
      .mockResolvedValueOnce(new Response('{}', { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);

    const pending = fetchWithEngineRecovery('/api/v1/agent-scan', { method: 'POST', body: '{}' }, 2);
    await vi.advanceTimersByTimeAsync(500);
    await expect(pending).resolves.toMatchObject({ status: 200 });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    vi.useRealTimers();
  });
});
