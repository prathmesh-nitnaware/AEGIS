import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5174,
    host: "0.0.0.0",
    strictPort: true,
  },
  resolve: {
    alias: {
      react: path.resolve(__dirname, "../dashboard/node_modules/react"),
      "react-dom": path.resolve(__dirname, "../dashboard/node_modules/react-dom"),
      "lucide-react": path.resolve(__dirname, "../dashboard/node_modules/lucide-react"),
    },
  },
});
