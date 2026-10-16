import { resolve } from "node:path"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

// Three pages: the landing page, the architecture walkthrough, and the original static mock.
export default defineConfig({
  plugins: [react()],
  // Tailscale Serve proxies https://<machine>.<tailnet>.ts.net:5197 here (tailnet only).
  server: { host: "127.0.0.1", port: Number(process.env.PORT) || 5197, strictPort: true, allowedHosts: [".ts.net"] },
  // knobs is linked from a local checkout (file:../../knobs) that has its own React for its tests.
  resolve: { dedupe: ["react", "react-dom"] },
  build: {
    rollupOptions: {
      input: {
        index: resolve(import.meta.dirname, "index.html"),
        architecture: resolve(import.meta.dirname, "architecture/index.html"),
        mock: resolve(import.meta.dirname, "mock.html"),
      },
    },
  },
})
