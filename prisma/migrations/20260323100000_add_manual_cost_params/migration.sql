-- AlterTable: Add manual cost parameter fields to Article
ALTER TABLE "Article" ADD COLUMN "manualBaseCost"        DECIMAL(14,4);
ALTER TABLE "Article" ADD COLUMN "manualCurrencyId"      TEXT;
ALTER TABLE "Article" ADD COLUMN "manualAdjustmentKind"  TEXT NOT NULL DEFAULT '';
ALTER TABLE "Article" ADD COLUMN "manualAdjustmentType"  TEXT NOT NULL DEFAULT '';
ALTER TABLE "Article" ADD COLUMN "manualAdjustmentValue" DECIMAL(14,4);
ALTER TABLE "Article" ADD COLUMN "manualTaxIds"          TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[];
