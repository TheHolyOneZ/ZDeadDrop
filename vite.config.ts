import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  base: "./",
  clearScreen: false,
  server: {
    port: 5183,
    strictPort: true,
  },
  build: {
    outDir: "dist",

    sourcemap: !!process.env.TAURI_DEBUG,
    target: "es2022",
  },
});
