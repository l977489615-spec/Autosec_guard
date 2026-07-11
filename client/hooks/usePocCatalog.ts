import { useEffect, useState } from 'react';
import { POC } from '../types';
import { fetchPocCatalog, normalizeCachedCatalogPoc } from '../services/pocCatalog';

let cachedCatalog: POC[] | null = null;

const restoreCatalogCache = (): POC[] | null => {
  return cachedCatalog;
};

const persistCatalogCache = (pocs: POC[]) => {
  cachedCatalog = pocs.map(normalizeCachedCatalogPoc);
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
