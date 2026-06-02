import { useEffect, useState } from 'react';
import { POC } from '../types';
import { fetchPocCatalog } from '../services/pocCatalog';

let cachedCatalog: POC[] | null = null;

export const usePocCatalog = () => {
  const [pocs, setPocs] = useState<POC[]>(cachedCatalog || []);
  const [loading, setLoading] = useState(!cachedCatalog);
  const [error, setError] = useState<string | null>(null);

  const refresh = async () => {
    setLoading(true);
    const result = await fetchPocCatalog();
    cachedCatalog = result.pocs;
    setPocs(result.pocs);
    setError(result.error || null);
    setLoading(false);
    return result.pocs;
  };

  useEffect(() => {
    if (!cachedCatalog) {
      refresh();
    }
  }, []);

  return { pocs, loading, error, refresh };
};
