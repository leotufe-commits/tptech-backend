-- Migration: add useManualSalePrice to Article
-- Adds an explicit boolean flag so that manual salePrice overrides
-- a calculated price list price. Default false = no override (safe).

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'Article' AND column_name = 'useManualSalePrice'
  ) THEN
    ALTER TABLE "Article" ADD COLUMN "useManualSalePrice" BOOLEAN NOT NULL DEFAULT false;
  END IF;
END $$;
