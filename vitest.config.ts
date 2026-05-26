import { defineConfig } from "vitest/config";
import { fileURLToPath, URL } from "node:url";

export default defineConfig({
  resolve: {
    alias: {
      // Submódulo tptech-shared (C1) — espejo del paths de tsconfig.json
      // para que los tests del renderer HTML (C4) puedan importar
      // `@tptech/shared/document-printables/SaleInvoicePrintable`.
      "@tptech/shared": fileURLToPath(new URL("../tptech-shared/src", import.meta.url)),
    },
  },
  test: {
    globals: true,
    environment: "node",
    include: ["src/**/__tests__/**/*.test.ts"],
    coverage: {
      provider: "v8",
      include: ["src/lib/pricing-engine/**"],
      exclude: ["src/lib/pricing-engine/__tests__/**"],
      reporter: ["text", "html"],
    },
  },
});
