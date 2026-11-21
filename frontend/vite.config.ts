import react from '@vitejs/plugin-react';
import { defineConfig, loadEnv, type Plugin } from 'vite';

/** Injects the API origin into the CSP `connect-src` so the browser may only talk to our own backend. */
function cspApiOrigin(apiUrl: string): Plugin {
  return {
    name: 'csp-api-origin',
    transformIndexHtml: (html) => html.replace('__API_ORIGIN__', new URL(apiUrl).origin),
  };
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '.', 'VITE_');
  // `||` (not `??`): an empty VITE_API_URL (unset CI variable) must fall back too.
  const apiUrl = env.VITE_API_URL || (mode === 'production' ? 'https://api.invalid' : 'http://localhost:8080');
  return {
    // Relative base so the same build works on GitHub Pages project sites and custom domains.
    base: './',
    plugins: [react(), cspApiOrigin(apiUrl)],
    server: { port: 5173, strictPort: true },
    build: { sourcemap: false, target: 'es2022' },
    test: { include: ['src/**/*.test.ts'], environment: 'node' },
  };
});
