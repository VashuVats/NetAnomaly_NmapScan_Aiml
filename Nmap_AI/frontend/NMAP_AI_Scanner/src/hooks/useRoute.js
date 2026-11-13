import { useEffect, useState } from 'react';

// Tiny client-side router: switches pages without reloading (keeps scan results in memory).
export const ROUTES = { scan: '/', traffic: '/analysis' };

export function navigate(path) {
  if (window.location.pathname !== path) {
    window.history.pushState({}, '', path);
    window.dispatchEvent(new PopStateEvent('popstate'));
  }
}

export function useRoute() {
  const [path, setPath] = useState(window.location.pathname);
  useEffect(() => {
    const onPop = () => setPath(window.location.pathname);
    window.addEventListener('popstate', onPop);
    return () => window.removeEventListener('popstate', onPop);
  }, []);
  return path === ROUTES.traffic ? 'traffic' : 'scan';
}
