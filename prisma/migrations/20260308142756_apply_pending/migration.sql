-- DropIndex
DROP INDEX "MetalQuote_variantId_currencyId_effectiveAt_idx";

-- CreateIndex
CREATE INDEX "MetalQuote_variantId_currencyId_effectiveAt_idx" ON "MetalQuote"("variantId", "currencyId", "effectiveAt");
