-- Remove redundant suggestedPrice from MetalVariantValueHistory
-- suggestedPrice = referenceValue * purity (computed dynamically, no need to store)
ALTER TABLE "MetalVariantValueHistory" DROP COLUMN IF EXISTS "suggestedPrice";
