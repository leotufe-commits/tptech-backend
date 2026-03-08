-- Composite index for fast "latest quote per variant per currency" queries
CREATE INDEX IF NOT EXISTS "MetalQuote_variantId_currencyId_effectiveAt_idx"
ON "MetalQuote" ("variantId", "currencyId", "effectiveAt" DESC);
