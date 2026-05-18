-- AlterTable
ALTER TABLE "Jewelry"
  ADD COLUMN IF NOT EXISTS "numberFormat" JSONB;
