// Service to communicate with the AutoSec backend / execution engine

const BACKEND_URL_STORAGE_KEY = 'autosec_backend_url';
const BACKEND_PORT = '5002';

const normalizeBackendUrl = (url: string) => url.replace(/\/$/, '');

const inferDefaultBackendUrl = () => {
  if (typeof window === 'undefined') {
    return `http://127.0.0.1:${BACKEND_PORT}`;
  }

  const protocol = window.location.protocol === 'https:' ? 'https:' : 'http:';
  const hostname = window.location.hostname || '127.0.0.1';
  return `${protocol}//${hostname}:${BACKEND_PORT}`;
};

const DEFAULT_BACKEND_URL = inferDefaultBackendUrl();

export interface UserAiSettings {
  baseUrl: string;
  apiKey: string;
  reportModel: string;
  fastModel: string;
  strongModel: string;
}

export const defaultAiSettings = (): UserAiSettings => ({
  baseUrl: 'https://dashscope.aliyuncs.com/compatible-mode/v1',
  apiKey: '',
  reportModel: 'qwen-max',
  fastModel: 'qwen-plus',
  strongModel: 'qwen-max',
});

export const buildAiConfigPayload = (settings?: Partial<UserAiSettings> | null) => {
  const resolved = {
    ...defaultAiSettings(),
    ...(settings || {}),
  };
  return {
    base_url: resolved.baseUrl.trim(),
    api_key: resolved.apiKey.trim(),
    report_model: resolved.reportModel.trim(),
    fast_model: resolved.fastModel.trim(),
    strong_model: resolved.strongModel.trim(),
  };
};

const resolveInitialBackendUrl = () => {
  if (typeof window === 'undefined') {
    return DEFAULT_BACKEND_URL;
  }

  const stored = window.localStorage.getItem(BACKEND_URL_STORAGE_KEY);
  if (stored) {
    const url = normalizeBackendUrl(stored);
    // If the stored URL points to localhost but the page is being accessed from a different host,
    // discard the stale stored value and use the dynamically resolved default.
    const isRemoteAccess = window.location.hostname !== 'localhost' && window.location.hostname !== '127.0.0.1';
    const storedIsLocal = url.includes('localhost') || url.includes('127.0.0.1');
    if (isRemoteAccess && storedIsLocal) {
      window.localStorage.removeItem(BACKEND_URL_STORAGE_KEY);
      return DEFAULT_BACKEND_URL;
    }
    return url;
  }
  return DEFAULT_BACKEND_URL;
};

// Default to localhost, but mutable via UI configuration
let backendUrl = resolveInitialBackendUrl();

export const setBackendUrl = (url: string) => {
  backendUrl = normalizeBackendUrl(url);
  if (typeof window !== 'undefined') {
    window.localStorage.setItem(BACKEND_URL_STORAGE_KEY, backendUrl);
  }
};

export const getBackendUrl = () => backendUrl;

const getRequestBackendUrl = (override?: string | null) => {
  if (override && override.trim()) {
    return normalizeBackendUrl(override.trim());
  }
  return backendUrl;
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
  vulnerable: boolean;
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
    const timeoutId = setTimeout(() => controller.abort(), 5002);

    console.log(`[API] Checking health at ${requestBackendUrl}/api/health`);

    const res = await fetch(`${requestBackendUrl}/api/health`, {
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
    console.error("[API] Health Check Failed:", e);
    return {
      ok: false,
      url: requestBackendUrl,
      error: e instanceof Error ? e.message : 'Unknown network error',
    };
  }
};

export const executePocScript = async (scriptContent: string, token?: string | null, backendOverride?: string | null): Promise<ExecutionResult> => {
  const requestBackendUrl = getRequestBackendUrl(backendOverride);
  try {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json'
    };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const res = await fetch(`${requestBackendUrl}/api/execute`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ script: scriptContent }),
      mode: 'cors'
    });

    if (!res.ok) {
      let message = `Server returned ${res.status}`;
      try {
        const data = await res.json();
        message = data.message || data.error || message;
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
  backendOverride?: string | null
): Promise<ExecutionResult> => {
  const requestBackendUrl = getRequestBackendUrl(backendOverride);
  try {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json'
    };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const res = await fetch(`${requestBackendUrl}/api/run_poc`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ filename, params }),
      mode: 'cors'
    });

    if (!res.ok) {
      let message = `Server returned ${res.status}`;
      try {
        const data = await res.json();
        message = data.message || data.error || message;
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

export const listPocs = async (): Promise<{ pocs: any[], total: number, error?: string }> => {
  try {
    const res = await fetch(`${backendUrl}/api/list_pocs`, {
      method: 'GET',
      mode: 'cors'
    });
    if (!res.ok) throw new Error(`Server returned ${res.status}`);
    return await res.json();
  } catch (error: any) {
    return { pocs: [], total: 0, error: error.message };
  }
};

export const fingerprintOS = async (ip: string): Promise<{ os: string; details: string; error?: string }> => {
  try {
    const res = await fetch(`${backendUrl}/api/fingerprint`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip }),
      mode: 'cors'
    });
    if (!res.ok) {
      throw new Error(`Server returned ${res.status}`);
    }
    return await res.json();
  } catch (error: any) {
    console.error('Failed to fingerprint OS:', error);
    return { os: 'unknown', details: 'Offline', error: error.message };
  }
};

export const saveScanSession = async (session: any, token: string | null) => {
  try {
    const res = await fetch(`${backendUrl}/api/save_session`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify(session),
      mode: 'cors'
    });
    return await res.json();
  } catch (error) {
    console.error('Failed to save session:', error);
    return { error: 'Connection failed' };
  }
};

export const fetchCurrentProfile = async (token: string) => {
  const res = await fetch(`${backendUrl}/api/profile`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`
    },
    mode: 'cors'
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.message || `Server returned ${res.status}`);
  }
  return data.user;
};

export const generateSecurityReport = async (session: any, token: string | null, aiSettings?: Partial<UserAiSettings> | null) => {
  try {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const res = await fetch(`${backendUrl}/api/report/generate`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ session, ai_config: buildAiConfigPayload(aiSettings) }),
      mode: 'cors',
    });

    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.message || `Server returned ${res.status}`);
    }

    return data.report as string;
  } catch (error: any) {
    console.error('Failed to generate AI report:', error);
    return 'AI 报告生成失败，请检查后端服务状态和当前用户的 AI 配置。';
  }
};

const postAssessment = async (path: string, session: any, token: string | null) => {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const res = await fetch(`${backendUrl}${path}`, {
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

export const generateAttackGraph = async (session: any, token: string | null) => {
  return postAssessment('/api/attack-graph/generate', session, token);
};

export const assessPhysicalImpact = async (session: any, token: string | null) => {
  return postAssessment('/api/physical-impact/assess', session, token);
};

export const simulateRemediation = async (session: any, token: string | null) => {
  return postAssessment('/api/remediation/simulate', session, token);
};

export const generateStructuredReport = async (session: any, token: string | null) => {
  return postAssessment('/api/report/structured', session, token);
};

const authedFetch = async (path: string, token: string | null, init?: RequestInit) => {
  const headers: Record<string, string> = {
    ...(init?.headers as Record<string, string> | undefined),
  };
  if (init?.body !== undefined && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  let res: Response;
  try {
    res = await fetch(`${backendUrl}${path}`, {
      ...init,
      headers,
      mode: 'cors',
    });
  } catch (error: any) {
    throw new Error(`Network request failed for ${path}: ${error?.message || 'Failed to fetch'}`);
  }

  const raw = await res.text();
  let data: any = {};
  try {
    data = raw ? JSON.parse(raw) : {};
  } catch {
    data = { raw };
  }

  if (!res.ok) {
    throw new Error(data.message || data.error || `Request ${path} failed with ${res.status}`);
  }
  return data;
};

export const getEdgeAgents = async (token: string | null) => {
  return authedFetch('/api/edge/agents', token, { method: 'GET' });
};

export const getEdgeTasks = async (token: string | null) => {
  return authedFetch('/api/edge/tasks', token, { method: 'GET' });
};

export const getEdgeRecommendations = async (
  filename: string,
  params: Record<string, any>,
  token: string | null
) => {
  return authedFetch('/api/edge/recommendations', token, {
    method: 'POST',
    body: JSON.stringify({ filename, params }),
  });
};

export const createEdgeTask = async (
  payload: {
    filename: string;
    params: Record<string, any>;
    agent_id?: string;
    session_id?: string;
    trace_id?: string;
  },
  token: string | null
) => {
  return authedFetch('/api/edge/tasks', token, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
};

export const generateEnrollmentToken = async (
  label: string,
  ttlHours: number,
  token: string | null
) => {
  return authedFetch('/api/edge/enrollment-tokens', token, {
    method: 'POST',
    body: JSON.stringify({ label, ttl_hours: ttlHours }),
  });
};

export const getEnrollmentTokens = async (token: string | null) => {
  return authedFetch('/api/edge/enrollment-tokens', token, { method: 'GET' });
};

export const revokeEnrollmentToken = async (tokenId: number, token: string | null) => {
  return authedFetch(`/api/edge/enrollment-tokens/${tokenId}`, token, { method: 'DELETE' });
};
