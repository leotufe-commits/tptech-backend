-- Migration: add_sale_qty_to_variant
-- Moves minSaleQuantity, maxSaleQuantity, defaultQuantity from Article to ArticleVariant.
-- The Article columns are kept intact (not dropped) for data safety; the UI no longer writes to them.

ALTER TABLE "ArticleVariant" ADD COLUMN IF NOT EXISTS "minSaleQuantity" DECIMAL(14,4);
ALTER TABLE "ArticleVariant" ADD COLUMN IF NOT EXISTS "maxSaleQuantity" DECIMAL(14,4);
ALTER TABLE "ArticleVariant" ADD COLUMN IF NOT EXISTS "defaultQuantity" DECIMAL(14,4);
