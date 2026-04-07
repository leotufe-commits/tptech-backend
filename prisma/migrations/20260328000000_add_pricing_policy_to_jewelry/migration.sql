-- AddColumn: pricing policy fields to Jewelry
ALTER TABLE "Jewelry"
  ADD COLUMN IF NOT EXISTS "pricingLowMarginWarningPercent"  DECIMAL(10,4),
  ADD COLUMN IF NOT EXISTS "pricingLowMarginBlockPercent"    DECIMAL(10,4),
  ADD COLUMN IF NOT EXISTS "pricingBlockLossSale"            BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS "pricingBlockZeroOrNegativePrice" BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS "pricingBlockPartialData"         BOOLEAN NOT NULL DEFAULT false;
