import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// In development the Hub runs on :8090 and Vite proxies the API and sign-in
// to it; `npm run build` writes dist/, which the Go binary embeds.
const hub = process.env.HUB_URL ?? 'http://localhost:8090';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { '/api': hub, '/auth': hub, '/signed-out': hub },
  },
  build: { outDir: 'dist', emptyOutDir: true, sourcemap: false },
});
