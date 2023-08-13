import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    coverage: {
      reporter: ['lcov', 'json', 'html', 'text-summary'],
    },
  },
})
