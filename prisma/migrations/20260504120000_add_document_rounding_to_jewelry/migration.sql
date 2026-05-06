-- AlterTable
ALTER TABLE "Jewelry"
  ADD COLUMN IF NOT EXISTS "documentRoundingEnabled"   BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS "documentRoundingMode"      "RoundingMode" NOT NULL DEFAULT 'NONE',
  ADD COLUMN IF NOT EXISTS "documentRoundingDirection" "RoundingDirection" NOT NULL DEFAULT 'NEAREST';
