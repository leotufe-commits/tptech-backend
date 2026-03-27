-- CreateEnum: CostCalculationMode
CREATE TYPE "CostCalculationMode" AS ENUM ('MANUAL', 'METAL_MERMA_HECHURA', 'MULTIPLIER');

-- CreateEnum: MultiplierBase
CREATE TYPE "MultiplierBase" AS ENUM ('GRAMS', 'KILATES', 'UNITS');

-- AlterTable Article: add cost calculation mode fields
ALTER TABLE "Article"
  ADD COLUMN "costCalculationMode" "CostCalculationMode" NOT NULL DEFAULT 'MANUAL',
  ADD COLUMN "multiplierBase"      "MultiplierBase",
  ADD COLUMN "multiplierValue"     DECIMAL(14,6),
  ADD COLUMN "multiplierQuantity"  DECIMAL(14,4);

-- CreateIndex for filtering by costCalculationMode
CREATE INDEX "Article_jewelryId_costCalculationMode_idx"
  ON "Article"("jewelryId", "costCalculationMode");
