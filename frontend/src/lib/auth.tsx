import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { api, ApiError, setCsrfToken, type Me } from './api';

interface AuthState {
  me: Me | null;
  loading: boolean;
  unreachable: boolean;
  refresh: () => Promise<void>;
  clear: () => void;
}
const Ctx = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);
  const [unreachable, setUnreachable] = useState(false);

  const refresh = useCallback(async () => {
    try {
      setMe(await api.me());
      setUnreachable(false);
    } catch (e) {
      setMe(null);
      setCsrfToken(null);
      setUnreachable(e instanceof ApiError && e.status === 0);
    } finally {
      setLoading(false);
    }
  }, []);
  const clear = useCallback(() => { setMe(null); setCsrfToken(null); }, []);

  useEffect(() => { void refresh(); }, [refresh]);
  const value = useMemo(() => ({ me, loading, unreachable, refresh, clear }), [me, loading, unreachable, refresh, clear]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth(): AuthState {
  const v = useContext(Ctx);
  if (!v) throw new Error('useAuth outside AuthProvider');
  return v;
}
