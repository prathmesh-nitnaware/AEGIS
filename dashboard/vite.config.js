import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
// VITE_COMMAND_NODE_URL: set at build time for Docker (via Dockerfile.dashboard ARG)
// Defaults to localhost:8000 for local development
export default defineConfig({
  plugins: [react()],
  server: {
    // Local dev proxy — forward API and WebSocket calls to backend
    proxy: {
      '/api': {
        target: process.env.VITE_COMMAND_NODE_URL || 'http://localhost:8000',
        changeOrigin: true,
      },
      '/ws': {
        target: (process.env.VITE_COMMAND_NODE_URL || 'http://localhost:8000').replace('http', 'ws'),
        changeOrigin: true,
        ws: true,
      },
    },
  },
})
