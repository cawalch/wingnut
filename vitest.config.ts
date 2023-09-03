import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    coverage: {
      provider: "istanbul",
      reporter: ["lcov", "json", "html", "text-summary"],
    },
  },
});
