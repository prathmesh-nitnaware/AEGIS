import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5174,
    host: "0.0.0.0",
    strictPort: true,
    proxy: {
      "/api": {
        target: process.env.VITE_COMMAND_NODE_URL || "http://127.0.0.1:8000",
        changeOrigin: true,
      },
      "/ws": {
        target: (process.env.VITE_COMMAND_NODE_URL || "http://127.0.0.1:8000").replace("http", "ws"),
        changeOrigin: true,
        ws: true,
      },
    },
  },
});
