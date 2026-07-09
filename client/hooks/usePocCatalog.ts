import { useEffect, useState } from 'react';
import { POC } from '../types';
import { fetchPocCatalog, normalizeCachedCatalogPoc } from '../services/pocCatalog';

let cachedCatalog: POC[] | null = null;
const POC_CATALOG_CACHE_VERSION = 3;
const LEGACY_POC_CATALOG_STORAGE_KEY = 'autosec_poc_catalog_cache';
const POC_CATALOG_STORAGE_KEY = `autosec_poc_catalog_cache_v${POC_CATALOG_CACHE_VERSION}`;

type StoredCatalogPayload = {
  version: number;
  pocs: POC[];
};

const restoreCatalogCache = (): POC[] | null => {
  if (cachedCatalog) return cachedCatalog;
  if (typeof window === 'undefined') return null;
  try {
    window.localStorage.removeItem(LEGACY_POC_CATALOG_STORAGE_KEY);
    const raw = window.localStorage.getItem(POC_CATALOG_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || parsed.version !== POC_CATALOG_CACHE_VERSION || !Array.isArray(parsed.pocs)) {
      return null;
    }
    return parsed.pocs.map(normalizeCachedCatalogPoc) as POC[];
  } catch {
    return null;
  }
};

const persistCatalogCache = (pocs: POC[]) => {
  cachedCatalog = pocs.map(normalizeCachedCatalogPoc);
  if (typeof window === 'undefined') return;
  try {
    const payload: StoredCatalogPayload = {
      version: POC_CATALOG_CACHE_VERSION,
      pocs: cachedCatalog,
    };
    window.localStorage.setItem(POC_CATALOG_STORAGE_KEY, JSON.stringify(payload));
  } catch {
    // ignore storage quota / serialization failures
  }
};

export const usePocCatalog = (token?: string | null) => {
  const initialCatalog = restoreCatalogCache();
  const [pocs, setPocs] = useState<POC[]>(initialCatalog || []);
  const [loading, setLoading] = useState(!initialCatalog);
  const [error, setError] = useState<string | null>(null);

  const refresh = async () => {
    setLoading(true);
    const result = await fetchPocCatalog(token);
    if (result.pocs.length > 0) {
      persistCatalogCache(result.pocs);
      setPocs(result.pocs);
    } else if (!result.error) {
      persistCatalogCache([]);
      setPocs([]);
    }
    setError(result.error || null);
    setLoading(false);
    return result.pocs.length > 0 ? result.pocs : (restoreCatalogCache() || []);
  };

  useEffect(() => {
    refresh();
  }, [token]);

  return { pocs, loading, error, refresh };
};
