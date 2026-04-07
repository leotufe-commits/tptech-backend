-- AlterTable: add dimension and sale quantity fields to Article
ALTER TABLE "Article"
  ADD COLUMN IF NOT EXISTS "dimensionLength"   DECIMAL(10,4),
  ADD COLUMN IF NOT EXISTS "dimensionWidth"    DECIMAL(10,4),
  ADD COLUMN IF NOT EXISTS "dimensionHeight"   DECIMAL(10,4),
  ADD COLUMN IF NOT EXISTS "dimensionUnit"     TEXT NOT NULL DEFAULT 'cm',
  ADD COLUMN IF NOT EXISTS "minSaleQuantity"   DECIMAL(14,4),
  ADD COLUMN IF NOT EXISTS "defaultQuantity"   DECIMAL(14,4);
