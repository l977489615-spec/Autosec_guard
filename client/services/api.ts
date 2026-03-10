// Service to communicate with the local Python execution engine

// Default to localhost, but mutable via UI configuration
let backendUrl = "http://localhost:5002";

export const setBackendUrl = (url: string) => {
  // Remove trailing slash if present
  backendUrl = url.replace(/\/$/, "");
};

export const getBackendUrl = () => backendUrl;

export interface ExecutionResult {
  success: boolean;
  logs: string[];
  errors: string[];
  vulnerable: boolean;
  return_code?: number;
  elapsed_seconds?: number;
}

export const checkBackendHealth = async (): Promise<boolean> => {
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
    return res.status === 200;
  } catch (e) {
    console.error("[API] Health Check Failed:", e);
    return false;
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