-- Add WEIGHT_UNIT value to CatalogType enum
ALTER TYPE "CatalogType" ADD VALUE IF NOT EXISTS 'WEIGHT_UNIT';

-- Add weight, weightUnit and inventoryAccount to Article
ALTER TABLE "Article"
  ADD COLUMN IF NOT EXISTS "weight"            DECIMAL(10,4),
  ADD COLUMN IF NOT EXISTS "weightUnit"        TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS "inventoryAccount"  TEXT NOT NULL DEFAULT '';
