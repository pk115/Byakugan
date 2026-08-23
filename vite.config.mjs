import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5173,
    proxy: {
      "/api": "http://localhost:3000"
    }
  },
  build: {
    outDir: "dist-web"
  },
  test: {
    exclude: ["**/node_modules/**", "outputs/**", "work/**", "dist-*/**"]
  }
});
