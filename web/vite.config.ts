import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  base: "./",
  build: {
    outDir: "../cmd/sahand-tunnel/web/dist",
    emptyOutDir: true
  }
});
