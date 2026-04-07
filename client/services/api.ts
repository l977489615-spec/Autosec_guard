// Service to communicate with the local Python execution engine

const BACKEND_URL_STORAGE_KEY = 'autosec_backend_url';
const DEFAULT_BACKEND_URL = 'http://localhost:5002';

const resolveInitialBackendUrl = () => {
  if (typeof window === 'undefined') {
    return DEFAULT_BACKEND_URL;
  }

  const stored = window.localStorage.getItem(BACKEND_URL_STORAGE_KEY);
  return stored ? stored.replace(/\/$/, '') : DEFAULT_BACKEND_URL;
};

// Default to localhost, but mutable via UI configuration
let backendUrl = resolveInitialBackendUrl();

export const setBackendUrl = (url: string) => {
  // Remove trailing slash if present
  backendUrl = url.replace(/\/$/, "");
  if (typeof window !== 'undefined') {
    window.localStorage.setItem(BACKEND_URL_STORAGE_KEY, backendUrl);
  }
};

export const getBackendUrl = () => backendUrl;

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

export const checkBackendHealth = async (): Promise<boolean> => {
  const health = await getBackendHealth();
  return health.ok;
};

export const getBackendHealth = async (): Promise<BackendHealthStatus> => {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5002);

    console.log(`[API] Checking health at ${backendUrl}/api/health`);

    const res = await fetch(`${backendUrl}/api/health`, {
      method: 'GET',
      signal: controller.signal,
      mode: 'cors'
    });
    clearTimeout(timeoutId);
    if (!res.ok) {
      return {
        ok: false,
        url: backendUrl,
        error: `Server returned ${res.status}`,
      };
    }
    const data = await res.json();
    return {
      ok: true,
      url: backendUrl,
      ...data,
    };
  } catch (e) {
    console.error("[API] Health Check Failed:", e);
    return {
      ok: false,
      url: backendUrl,
      error: e instanceof Error ? e.message : 'Unknown network error',
    };
  }
};

export const executePocScript = async (scriptContent: string, token?: string | null): Promise<ExecutionResult> => {
  try {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json'
    };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const res = await fetch(`${backendUrl}/api/execute`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ script: scriptContent }),
      mode: 'cors'
    });

    if (!res.ok) {
      throw new Error(`Server returned ${res.status}`);
    }

    return await res.json();
  } catch (error: any) {
    return {
      success: false,
      logs: [],
      errors: [`Network Error: Could not connect to execution engine at ${backendUrl}`, error.message],
      vulnerable: false
    };
  }
};

export const runPocPlugin = async (filename: string, params: Record<string, any>, token?: string | null): Promise<ExecutionResult> => {
  try {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json'
    };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const res = await fetch(`${backendUrl}/api/run_poc`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ filename, params }),
      mode: 'cors'
    });

    if (!res.ok) {
      throw new Error(`Server returned ${res.status}`);
    }

    return await res.json();
  } catch (error: any) {
    return {
      success: false,
      logs: [],
      errors: [`Network Error: Could not connect to execution engine at ${backendUrl}`, error.message],
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

export const generateSecurityReport = async (session: any, token: string | null) => {
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
      body: JSON.stringify({ session }),
      mode: 'cors',
    });

    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.message || `Server returned ${res.status}`);
    }

    return data.report as string;
  } catch (error: any) {
    console.error('Failed to generate AI report:', error);
    return 'AI 报告生成失败，请检查后端服务状态和服务端模型配置。';
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
