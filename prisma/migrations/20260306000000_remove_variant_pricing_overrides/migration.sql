-- Migration: remove_variant_pricing_overrides
-- Removes purchase/override pricing fields from MetalVariant and MetalQuote.
-- MetalQuote: merges purchasePrice+salePrice into a single `price` field (using salePrice as the canonical value).

-- Step 1: Add `price` column with a default derived from existing salePrice
ALTER TABLE "MetalQuote" ADD COLUMN "price" DECIMAL(18,6);
UPDATE "MetalQuote" SET "price" = "salePrice";
ALTER TABLE "MetalQuote" ALTER COLUMN "price" SET NOT NULL;

-- Step 2: Drop old columns from MetalQuote
ALTER TABLE "MetalQuote" DROP COLUMN "purchasePrice";
ALTER TABLE "MetalQuote" DROP COLUMN "salePrice";

-- Step 3: Drop override/pricing columns from MetalVariant
ALTER TABLE "MetalVariant" DROP COLUMN IF EXISTS "buyFactor";
ALTER TABLE "MetalVariant" DROP COLUMN IF EXISTS "purchasePriceOverride";
ALTER TABLE "MetalVariant" DROP COLUMN IF EXISTS "salePriceOverride";
ALTER TABLE "MetalVariant" DROP COLUMN IF EXISTS "pricingMode";

-- Step 4: Drop removed columns from MetalVariantValueHistory
ALTER TABLE "MetalVariantValueHistory" DROP COLUMN IF EXISTS "buyFactor";
ALTER TABLE "MetalVariantValueHistory" DROP COLUMN IF EXISTS "purchasePriceOverride";
ALTER TABLE "MetalVariantValueHistory" DROP COLUMN IF EXISTS "salePriceOverride";
ALTER TABLE "MetalVariantValueHistory" DROP COLUMN IF EXISTS "pricingMode";
ALTER TABLE "MetalVariantValueHistory" DROP COLUMN IF EXISTS "finalPurchasePrice";

-- Step 5: Drop VariantPricingMode enum if it exists
DROP TYPE IF EXISTS "VariantPricingMode";
