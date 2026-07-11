// Service to communicate with the AutoSec backend / execution engine

export interface UserAiSettings {
  baseUrl: string;
  apiKey: string;
  apiKeyConfigured?: boolean;
  reportModel: string;
  fastModel: string;
  strongModel: string;
}

export const defaultAiSettings = (): UserAiSettings => ({
  baseUrl: '',
  apiKey: '',
  reportModel: '',
  fastModel: '',
  strongModel: '',
});

/** UI 占位示例：任意 OpenAI 兼容服务商均可使用 */
export const AI_CONFIG_PLACEHOLDERS = {
  baseUrl: 'https://api.openai.com/v1',
  reportModel: '报告模型（如 gpt-4o）',
  fastModel: '快速模型（如 gpt-4o-mini）',
  strongModel: '强推理模型（如 o1 / deepseek-reasoner）',
} as const;

export const buildAiConfigPayload = (settings?: Partial<UserAiSettings> | null, options?: { includeApiKey?: boolean }) => {
  const resolved = {
    ...defaultAiSettings(),
    ...(settings || {}),
  };
  const includeKey = options?.includeApiKey ?? false;
  const payload: Record<string, string> = {
    base_url: resolved.baseUrl.trim(),
    report_model: resolved.reportModel.trim(),
    fast_model: resolved.fastModel.trim(),
    strong_model: resolved.strongModel.trim(),
  };
  // 默认不向服务端发送 api_key；服务端从加密存储加载
  if (includeKey && resolved.apiKey.trim()) {
    payload.api_key = resolved.apiKey.trim();
  }
  return payload;
};

// v3 is a same-origin edge workstation. The API is never redirected by browser state.
const backendUrl = '';

// 全局 401 回调：由 App.tsx 注册，所有 API 调用遇 401 时触发登出
let _onUnauthorized: (() => void) | null = null;
export const setUnauthorizedHandler = (handler: () => void) => {
  _onUnauthorized = handler;
};

const handleResponseAuth = (res: Response) => {
  if (res.status === 401 && _onUnauthorized) {
    _onUnauthorized();
  }
};

export class ApiRequestError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly code?: string,
    public readonly traceId?: string,
    public readonly retryAfterSeconds?: number,
  ) {
    super(message);
    this.name = 'ApiRequestError';
  }
}

export const COOKIE_SESSION_SENTINEL = 'cookie-session';

const isBearerToken = (token?: string | null): token is string =>
  Boolean(token && token !== COOKIE_SESSION_SENTINEL);

const buildAuthHeaders = (token?: string | null, extra?: Record<string, string>): Record<string, string> => {
  const headers: Record<string, string> = { 'Content-Type': 'application/json', ...(extra || {}) };
  if (isBearerToken(token)) headers['Authorization'] = `Bearer ${token}`;
  return headers;
};

export const getBackendUrl = () => '';

export interface AuthStatus {
  user_count: number;
  bootstrap_required: boolean;
  bootstrap_mode: 'edge' | 'cli_only' | string;
  web_bootstrap_allowed: boolean;
  open_registration: boolean;
  registration_allowed: boolean;
  bootstrap_token_required: boolean;
  registration_scope?: 'local' | 'configured' | 'disabled' | string;
}

type AuthAction = 'login' | 'register';

export const submitAuth = async (
  action: AuthAction,
  payload: Record<string, string>,
): Promise<any> => {
  const res = await fetch(`/api/v1/auth/${action}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
    credentials: 'same-origin',
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new ApiRequestError(
      data?.error?.message || data?.message || (action === 'login' ? '登录失败，请检查账号和密码。' : '注册失败。'),
      res.status,
      data?.error?.code,
      data?.trace_id,
    );
  }
  return data;
};

export const getAuthStatus = async (backendOverride?: string | null): Promise<AuthStatus> => {
  const base = getRequestBackendUrl(backendOverride);
  const res = await fetch(`${base}/api/v1/auth/status`, { method: 'GET', credentials: 'same-origin' });
  if (!res.ok) {
    throw new Error(`Server returned ${res.status}`);
  }
  return await res.json();
};

const getRequestBackendUrl = (_override?: string | null) => backendUrl;

const ENGINE_RECOVERY_DELAYS_MS = [500, 1_000, 2_000, 4_000, 8_000];

/** Retry only requests whose caller has established replay safety/idempotency. */
export const fetchWithEngineRecovery = async (
  input: RequestInfo | URL,
  init?: RequestInit,
  maxAttempts: number = ENGINE_RECOVERY_DELAYS_MS.length + 1,
): Promise<Response> => {
  let lastError: unknown;
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    if (init?.signal?.aborted) throw new DOMException('Request aborted', 'AbortError');
    try {
      const response = await fetch(input, init);
      if (![502, 503, 504].includes(response.status) || attempt === maxAttempts - 1) return response;
      lastError = new Error(`Execution Engine temporarily unavailable (${response.status})`);
    } catch (error) {
      if (init?.signal?.aborted) throw error;
      lastError = error;
      if (attempt === maxAttempts - 1) throw error;
    }
    const delay = ENGINE_RECOVERY_DELAYS_MS[Math.min(attempt, ENGINE_RECOVERY_DELAYS_MS.length - 1)];
    await new Promise(resolve => window.setTimeout(resolve, delay));
  }
  throw lastError || new Error('Execution Engine recovery timed out');
};

export interface BackendHealthStatus {
  ok: boolean;
  url: string;
  status?: string;
  system?: string;
  database?: string;
  ai_reports_enabled?: boolean;
  warnings?: string[];
  error?: string;
}

export interface ExecutionResult {
  success: boolean;
  logs: string[];
  errors: string[];
  vulnerable: boolean | null;
  evidence?: string;
  cve_id?: string;
  poc_id?: string;
  trace_id?: string;
  requires_human_review?: boolean;
  requires_disruptive_approval?: boolean;
  requires_post_execution_review?: boolean;
  manual_confirmation_required?: boolean;
  validation_tier?: string;
  detection_confidence?: number;
  execution_safety?: string;
  exp_capability?: string;
  professional_policy?: Record<string, any>;
  verification_status?: string;
  manual_review?: {
    state: string;
    verdict?: string;
    prompt?: string;
    required_observations?: string[];
    verdict_options?: string[];
    operator_note?: string;
    evidence_file?: string;
    reviewed_at?: string;
  };
  return_code?: number;
  elapsed_seconds?: number;
}

export const checkBackendHealth = async (backendOverride?: string | null): Promise<boolean> => {
  const health = await getBackendHealth(backendOverride);
  return health.ok;
};

export const getBackendHealth = async (backendOverride?: string | null): Promise<BackendHealthStatus> => {
  const requestBackendUrl = getRequestBackendUrl(backendOverride);
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10_000);

    const res = await fetch(`${requestBackendUrl}/health`, {
      method: 'GET',
      signal: controller.signal,
      mode: 'cors'
    });
    clearTimeout(timeoutId);
    if (!res.ok) {
      return {
        ok: false,
        url: requestBackendUrl,
        error: `Server returned ${res.status}`,
      };
    }
    const data = await res.json();
    return {
      ok: true,
      url: requestBackendUrl,
      ...data,
    };
  } catch (e) {
    const aborted = e instanceof DOMException && e.name === 'AbortError';
    return {
      ok: false,
      url: requestBackendUrl,
      error: aborted ? '本机引擎响应超时，正在重试。' : (e instanceof Error ? e.message : '无法连接本机引擎。'),
    };
  }
};

export const executePocScript = async (scriptContent: string, token?: string | null, backendOverride?: string | null): Promise<ExecutionResult> => {
  const requestBackendUrl = getRequestBackendUrl(backendOverride);
  try {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json'
    };
    if (isBearerToken(token)) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const res = await fetch(`${requestBackendUrl}/api/v1/execute`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ script: scriptContent }),
      mode: 'cors'
    });

    if (!res.ok) {
      let message = `Server returned ${res.status}`;
      try {
        const data = await res.json();
        message = data?.error?.message || data.message || data.error || message;
      } catch {
        // Ignore JSON parse failures and keep the HTTP status message.
      }
      throw new Error(message);
    }

    return await res.json();
  } catch (error: any) {
    const message = error?.message || 'Unknown error';
    const isNetworkError = /Failed to fetch|NetworkError|aborted|Load failed|Could not connect/i.test(message);
    return {
      success: false,
      logs: [],
      errors: [isNetworkError ? `Network Error: Could not connect to execution engine at ${requestBackendUrl}` : message],
      vulnerable: false
    };
  }
};

export const runPocPlugin = async (
  filename: string,
  params: Record<string, any>,
  token?: string | null,
  backendOverride?: string | null,
  sessionId?: string | null,
): Promise<ExecutionResult> => {
  const requestBackendUrl = getRequestBackendUrl(backendOverride);
  try {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json'
    };
    if (isBearerToken(token)) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const res = await fetch(`${requestBackendUrl}/api/v1/run_poc`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ filename, params, ...(sessionId ? { session_id: sessionId } : {}) }),
      mode: 'cors'
    });

    if (!res.ok) {
      let message = `Server returned ${res.status}`;
      try {
        const data = await res.json();
        message = data?.error?.message || data.message || data.error || message;
      } catch {
        // Ignore JSON parse failures and keep the HTTP status message.
      }
      throw new Error(message);
    }

    return await res.json();
  } catch (error: any) {
    const message = error?.message || 'Unknown error';
    const isNetworkError = /Failed to fetch|NetworkError|aborted|Load failed|Could not connect/i.test(message);
    return {
      success: false,
      logs: [],
      errors: [isNetworkError ? `Network Error: Could not connect to execution engine at ${requestBackendUrl}` : message],
      vulnerable: false
    };
  }
};

export const submitPocManualVerdict = async (
  payload: {
    trace_id?: string;
    session_id?: string;
    poc_id?: string;
    poc_name?: string;
    target_ip?: string;
    target_mac?: string;
    bluetooth_mac?: string;
    verdict: 'confirmed_vulnerable' | 'confirmed_not_vulnerable' | 'inconclusive' | 'needs_retest';
    operator_note?: string;
    evidence_file?: string;
  },
  token?: string | null,
  backendOverride?: string | null
): Promise<ExecutionResult> => {
  const requestBackendUrl = getRequestBackendUrl(backendOverride);
  try {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json'
    };
    if (isBearerToken(token)) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const res = await fetch(`${requestBackendUrl}/api/v1/poc_manual_verdict`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
      mode: 'cors'
    });

    if (!res.ok) {
      let message = `Server returned ${res.status}`;
      try {
        const data = await res.json();
        message = data?.error?.message || data.message || data.error || message;
      } catch {
        // Keep HTTP status message.
      }
      throw new Error(message);
    }

    return await res.json();
  } catch (error: any) {
    return {
      success: false,
      logs: [],
      errors: [error?.message || 'Failed to submit manual verdict.'],
      vulnerable: null
    };
  }
};

export const submitPocManualVerdictBatch = async (
  payload: {
    session_id?: string;
    target_ip?: string;
    target_mac?: string;
    bluetooth_mac?: string;
    operator_note?: string;
    evidence_file?: string;
    items: Array<{
      trace_id?: string;
      poc_id?: string;
      poc_name?: string;
      verdict: 'confirmed_vulnerable' | 'confirmed_not_vulnerable' | 'inconclusive' | 'needs_retest';
      operator_note?: string;
      evidence_file?: string;
    }>;
  },
  token?: string | null,
  backendOverride?: string | null
): Promise<{ success: boolean; count?: number; results?: ExecutionResult[]; error?: string }> => {
  const requestBackendUrl = getRequestBackendUrl(backendOverride);
  try {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (isBearerToken(token)) headers['Authorization'] = `Bearer ${token}`;
    const res = await fetch(`${requestBackendUrl}/api/v1/poc_manual_verdict_batch`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
      mode: 'cors'
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data?.error?.message || data.message || data.error || `Server returned ${res.status}`);
    }
    return await res.json();
  } catch (error: any) {
    return { success: false, error: error?.message || 'Failed to submit batch manual verdict.' };
  }
};

export const recordScanApprovalPolicy = async (
  payload: {
    session_id: string;
    target_ip?: string;
    min_tier?: string;
    max_tier?: string;
    allow_lab_exp?: boolean;
    allow_auto_exp?: boolean;
    allow_disruptive?: boolean;
  },
  token?: string | null,
  backendOverride?: string | null
): Promise<{ success: boolean; policy?: Record<string, any>; error?: string }> => {
  const requestBackendUrl = getRequestBackendUrl(backendOverride);
  try {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (isBearerToken(token)) headers['Authorization'] = `Bearer ${token}`;
    const res = await fetch(`${requestBackendUrl}/api/v1/scan_approval_policy`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
      mode: 'cors'
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data?.error?.message || data.message || data.error || `Server returned ${res.status}`);
    }
    return await res.json();
  } catch (error: any) {
    return { success: false, error: error?.message || 'Failed to record scan approval policy.' };
  }
};

export const listPocs = async (token?: string | null): Promise<{ pocs: any[], total: number, error?: string }> => {
  try {
    const res = await fetch(`${backendUrl}/api/v1/list_pocs`, {
      method: 'GET',
      headers: buildAuthHeaders(token),
      mode: 'cors'
    });
    handleResponseAuth(res);
    if (!res.ok) throw new Error(`Server returned ${res.status}`);
    return await res.json();
  } catch (error: any) {
    return { pocs: [], total: 0, error: error.message };
  }
};

export const fingerprintOS = async (ip: string, token?: string | null): Promise<{ os: string; details: string; error?: string }> => {
  try {
    const res = await fetch(`${backendUrl}/api/v1/fingerprint`, {
      method: 'POST',
      headers: buildAuthHeaders(token),
      body: JSON.stringify({ ip }),
      mode: 'cors'
    });
    handleResponseAuth(res);
    if (!res.ok) {
      throw new Error(`Server returned ${res.status}`);
    }
    return await res.json();
  } catch (error: any) {
    console.error('Failed to fingerprint OS:', error);
    return { os: 'unknown', details: 'Offline', error: error.message };
  }
};

export const saveScanSession = async (session: any, token: string | null): Promise<{ success: boolean; error?: string }> => {
  try {
    // Upsert by session id, therefore safe to replay after an engine restart.
    const res = await fetchWithEngineRecovery(`${backendUrl}/api/v1/save_session`, {
      method: 'POST',
      headers: buildAuthHeaders(token),
      body: JSON.stringify(session),
      mode: 'cors'
    });
    handleResponseAuth(res);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      return { success: false, error: data?.error?.message || data.message || data.error || `Server returned ${res.status}` };
    }
    return { success: true };
  } catch (error: any) {
    console.error('Failed to save session:', error);
    return { success: false, error: error?.message || 'Connection failed' };
  }
};

export const fetchCurrentProfile = async (token?: string | null) => {
  const res = await fetch(`${backendUrl}/api/v1/profile`, {
    method: 'GET',
    headers: buildAuthHeaders(token),
    credentials: 'same-origin',
    mode: 'cors'
  });

  const data = await res.json();
  handleResponseAuth(res);
  if (!res.ok) {
    throw new Error(data?.error?.message || data.message || `Server returned ${res.status}`);
  }
  return data.user;
};

export const logoutCurrentSession = async (): Promise<void> => {
  const res = await fetch(`${backendUrl}/api/v1/auth/logout`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
  });
  if (!res.ok && res.status !== 401) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data?.error?.message || '退出失败。');
  }
};

export const generateSecurityReport = async (session: any, token: string | null, aiSettings?: Partial<UserAiSettings> | null): Promise<{ success: boolean; report?: string; error?: string }> => {
  try {
    const res = await fetch(`${backendUrl}/api/v1/report/generate`, {
      method: 'POST',
      headers: buildAuthHeaders(token),
      // 不传 api_key：服务端从用户加密存储加载
      body: JSON.stringify({ session, ai_config: buildAiConfigPayload(aiSettings) }),
      mode: 'cors',
    });
    handleResponseAuth(res);
    const data = await res.json();
    if (!res.ok) {
      return { success: false, error: data.message || `Server returned ${res.status}` };
    }
    return { success: true, report: data.report as string };
  } catch (error: any) {
    console.error('Failed to generate AI report:', error);
    return { success: false, error: error?.message || 'AI 报告生成失败，请检查后端服务状态和当前用户的 AI 配置。' };
  }
};

const postAssessment = async (path: string, session: any, token: string | null) => {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (isBearerToken(token)) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  // Assessment artifact generation is pure for the supplied session snapshot.
  const res = await fetchWithEngineRecovery(`${backendUrl}${path}`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ session }),
    mode: 'cors',
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.message || `Server returned ${res.status}`);
  }
  return data;
};

export interface ProfileUpdatePayload {
  new_username?: string;
  new_password?: string;
  ai_config?: Record<string, string>;
}

export const updateCurrentProfile = async (token: string | null, payload: ProfileUpdatePayload) => {
  return authedFetch('/api/v1/profile', token, {
    method: 'PUT',
    body: JSON.stringify(payload),
  });
};

export const testCurrentAiConfig = async (token: string | null, aiConfig: Record<string, string>) => {
  return authedFetch('/api/v1/test-ai-config', token, {
    method: 'POST',
    body: JSON.stringify({ ai_config: aiConfig }),
  });
};

export const generateAttackGraph = async (session: any, token: string | null) => {
  return postAssessment('/api/v1/attack-graph/generate', session, token);
};

export const generateMultiHopAttackGraph = async (session: any, token: string | null) => {
  return postAssessment('/api/v1/attack-graph/multihop', session, token);
};

export const assessPhysicalImpact = async (session: any, token: string | null) => {
  return postAssessment('/api/v1/physical-impact/assess', session, token);
};

export const simulateRemediation = async (session: any, token: string | null) => {
  return postAssessment('/api/v1/remediation/simulate', session, token);
};

export const generateStructuredReport = async (session: any, token: string | null) => {
  return postAssessment('/api/v1/report/structured', session, token);
};

const authedFetch = async (path: string, token: string | null, init?: RequestInit) => {
  const headers: Record<string, string> = {
    ...(init?.headers as Record<string, string> | undefined),
  };
  if (init?.body !== undefined && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }
  if (isBearerToken(token)) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const controller = new AbortController();
  const timeoutId = window.setTimeout(() => controller.abort('request-timeout'), 15_000);
  const abortFromCaller = () => controller.abort(init?.signal?.reason || 'request-cancelled');
  init?.signal?.addEventListener('abort', abortFromCaller, { once: true });
  let res: Response;
  try {
    res = await fetch(`${backendUrl}${path}`, {
      ...init,
      headers,
      signal: controller.signal,
      credentials: 'same-origin',
      mode: 'cors',
    });
  } catch (error: any) {
    const message = controller.signal.aborted ? '请求已取消或超时。' : (error?.message || 'Failed to fetch');
    throw new ApiRequestError(message, 0, controller.signal.reason === 'request-timeout' ? 'REQUEST_TIMEOUT' : 'NETWORK_ERROR');
  } finally {
    window.clearTimeout(timeoutId);
    init?.signal?.removeEventListener('abort', abortFromCaller);
  }

  const raw = await res.text();
  handleResponseAuth(res);
  let data: any = {};
  try {
    data = raw ? JSON.parse(raw) : {};
  } catch {
    data = { raw };
  }

  if (!res.ok) {
    const retryAfter = Number(res.headers.get('Retry-After') || 0) || undefined;
    throw new ApiRequestError(
      data?.error?.message || data.message || `Request ${path} failed with ${res.status}`,
      res.status,
      data?.error?.code,
      data?.trace_id,
      retryAfter,
    );
  }
  return data;
};

export const getLocalCapabilities = async (token: string | null) => {
  return authedFetch('/api/v1/local/capabilities', token, { method: 'GET' });
};

export interface SessionSummary {
  counts: Record<string, number>;
  confirmed_findings: number;
  recent_failures: Array<{ id: string; status: string; target?: Record<string, string>; updated_at?: string }>;
}

export const getSessionSummary = async (token?: string | null): Promise<SessionSummary> => {
  return authedFetch('/api/v1/sessions/summary', token || null, { method: 'GET' });
};

export const listV3Sessions = async (token?: string | null): Promise<V3Session[]> => {
  const data = await authedFetch('/api/v1/sessions', token || null, { method: 'GET' });
  return Array.isArray(data.sessions) ? data.sessions as V3Session[] : [];
};

export const getV3Session = async (sessionId: string, token?: string | null): Promise<V3Session> => {
  const data = await authedFetch(`/api/v1/sessions/${encodeURIComponent(sessionId)}`, token || null, { method: 'GET' });
  return data.session as V3Session;
};

export interface LegacyHistoryRecord {
  id: number;
  user_id: number;
  username?: string;
  session_id?: string | null;
  target_ip?: string | null;
  target_mac?: string | null;
  status?: string;
  started_at?: string | null;
  completed_at?: string | null;
  risk_score?: number;
  results_json?: Record<string, unknown>;
  logs?: unknown[];
  findings?: unknown[];
  phase_records?: unknown[];
  structured?: Record<string, unknown>;
}

export const listLegacyHistory = async (token?: string | null): Promise<LegacyHistoryRecord[]> => {
  const data = await authedFetch('/api/v1/history', token || null, { method: 'GET' });
  return Array.isArray(data.history) ? data.history as LegacyHistoryRecord[] : [];
};

export const getV3SessionArtifacts = async (sessionId: string, token?: string | null) => {
  const data = await authedFetch(`/api/v1/sessions/${encodeURIComponent(sessionId)}/artifacts`, token || null, { method: 'GET' });
  return Array.isArray(data.artifacts) ? data.artifacts : [];
};

export const getV3SessionEventsSnapshot = async (sessionId: string, token?: string | null): Promise<V3SessionEvent[]> => {
  const headers: Record<string, string> = { Accept: 'text/event-stream' };
  if (token && token !== 'cookie-session') headers.Authorization = `Bearer ${token}`;
  const response = await fetch(`/api/v1/sessions/${encodeURIComponent(sessionId)}/events`, {
    headers,
    credentials: 'same-origin',
  });
  handleResponseAuth(response);
  if (!response.ok) {
    let data: any = {};
    try { data = await response.json(); } catch { /* keep fallback */ }
    throw new ApiRequestError(data?.error?.message || '读取会话时间线失败。', response.status, data?.error?.code, data?.trace_id);
  }
  const text = await response.text();
  return text.split('\n\n').flatMap(frame => {
    const rawData = frame.match(/^data:\s*(.+)$/m)?.[1];
    if (!rawData) return [];
    try { return [JSON.parse(rawData) as V3SessionEvent]; } catch { return []; }
  });
};

export interface V3Session {
  id: string;
  mode: 'manual' | 'batch' | 'agent';
  status: string;
  target: Record<string, unknown>;
  policy: Record<string, unknown>;
  result?: Record<string, any>;
  plan?: Array<Record<string, any>>;
  created_at?: string;
  updated_at?: string;
  started_at?: string;
  completed_at?: string;
}

export interface V3SessionEvent {
  id: number;
  event_type: string;
  payload: Record<string, unknown>;
  created_at?: string;
}

export const subscribeV3SessionEvents = async (
  sessionId: string,
  onEvent: (event: V3SessionEvent) => void,
  signal: AbortSignal,
  token?: string | null,
): Promise<void> => {
  let after = 0;
  while (!signal.aborted) {
    const headers: Record<string, string> = { Accept: 'text/event-stream' };
    if (token && token !== 'cookie-session') headers.Authorization = `Bearer ${token}`;
    const response = await fetch(
      `/api/v1/sessions/${encodeURIComponent(sessionId)}/events?after=${after}`,
      { headers, credentials: 'same-origin', signal },
    );
    handleResponseAuth(response);
    if (!response.ok || !response.body) {
      let data: any = {};
      try { data = await response.json(); } catch { /* preserve status fallback */ }
      throw new ApiRequestError(
        data?.error?.message || '会话事件订阅失败。',
        response.status,
        data?.error?.code,
        data?.trace_id,
      );
    }
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    while (!signal.aborted) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const frames = buffer.split('\n\n');
      buffer = frames.pop() || '';
      for (const frame of frames) {
        const id = Number(frame.match(/^id:\s*(\d+)/m)?.[1] || 0);
        const rawData = frame.match(/^data:\s*(.+)$/m)?.[1];
        if (!id || !rawData) continue;
        const event = JSON.parse(rawData) as V3SessionEvent;
        after = Math.max(after, id);
        onEvent(event);
      }
    }
    if (!signal.aborted) await new Promise(resolve => window.setTimeout(resolve, 1_000));
  }
};

export const createV3Session = async (
  mode: V3Session['mode'],
  target: Record<string, unknown>,
  policy: Record<string, unknown>,
  token?: string | null,
): Promise<V3Session> => {
  let lastError: unknown;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      const data = await authedFetch('/api/v1/sessions', token || null, {
        method: 'POST',
        body: JSON.stringify({ mode, target, policy }),
      });
      return data.session as V3Session;
    } catch (error: any) {
      lastError = error;
      const retryable = error instanceof ApiRequestError
        && (error.status === 503 || error.code === 'DATABASE_BUSY');
      if (!retryable || attempt === 2) throw error;
      await new Promise(resolve => window.setTimeout(resolve, 250 * (attempt + 1)));
    }
  }
  throw lastError;
};

export const startV3SessionRun = async (sessionId: string, token?: string | null): Promise<V3Session> => {
  const data = await authedFetch(`/api/v1/sessions/${encodeURIComponent(sessionId)}/runs`, token || null, {
    method: 'POST',
    body: JSON.stringify({}),
  });
  return data.session as V3Session;
};

export type V3RunAction = 'await_review' | 'complete' | 'fail' | 'cancel';

export const updateV3SessionRun = async (
  sessionId: string,
  action: V3RunAction,
  result: Record<string, unknown> = {},
  token?: string | null,
): Promise<V3Session> => {
  let lastError: unknown;
  for (let attempt = 0; attempt < 4; attempt += 1) {
    try {
      const data = await authedFetch(`/api/v1/sessions/${encodeURIComponent(sessionId)}/runs`, token || null, {
        method: 'POST',
        body: JSON.stringify({ action, result }),
      });
      return data.session as V3Session;
    } catch (error: any) {
      lastError = error;
      // A response can be lost after the server committed the transition.
      // Reconcile against authoritative state before deciding that it failed.
      if (error instanceof ApiRequestError && error.status === 409) {
        const expected = { await_review: 'awaiting_review', complete: 'completed', fail: 'failed', cancel: 'cancelled' }[action];
        const current = await getV3Session(sessionId, token).catch(() => null);
        if (current?.status === expected) return current;
      }
      const retryable = error instanceof ApiRequestError
        && (error.status === 0 || error.status === 502 || error.status === 503 || error.status === 504 || error.code === 'DATABASE_BUSY');
      if (!retryable || attempt === 3) throw error;
      await new Promise(resolve => window.setTimeout(resolve, 500 * (2 ** attempt)));
    }
  }
  throw lastError;
};

export const approveV3SessionAction = async (
  sessionId: string,
  pocFilename: string,
  target: string,
  token?: string | null,
  riskLevel: string = 'RESTART',
): Promise<string> => {
  const data = await authedFetch(`/api/v1/sessions/${encodeURIComponent(sessionId)}/approvals`, token || null, {
    method: 'POST',
    body: JSON.stringify({ poc_filename: pocFilename, target, risk_ceiling: riskLevel }),
  });
  return String(data.approval_token || '');
};

export const submitV3SessionReview = async (
  sessionId: string,
  review: {
    trace_id?: string;
    poc_id?: string;
    verdict: 'confirmed_vulnerable' | 'confirmed_not_vulnerable' | 'inconclusive' | 'needs_retest';
    operator_note?: string;
    evidence_file?: string;
  },
  token?: string | null,
): Promise<V3Session> => {
  const data = await authedFetch(`/api/v1/sessions/${encodeURIComponent(sessionId)}/reviews`, token || null, {
    method: 'POST',
    body: JSON.stringify(review),
  });
  return data.session as V3Session;
};
