-- AlterTable
ALTER TABLE "LabelElement" ALTER COLUMN "updatedAt" DROP DEFAULT;

-- AlterTable
ALTER TABLE "LabelTemplate" ALTER COLUMN "updatedAt" DROP DEFAULT;

-- AlterTable (IF NOT EXISTS: columnas pueden ya existir de migración anterior)
ALTER TABLE "PrinterProfile" ADD COLUMN IF NOT EXISTS "offsetXMm" DECIMAL(8,2) NOT NULL DEFAULT 0,
ADD COLUMN IF NOT EXISTS "offsetYMm" DECIMAL(8,2) NOT NULL DEFAULT 0;
ALTER TABLE "PrinterProfile" ALTER COLUMN "updatedAt" DROP DEFAULT;

-- AlterTable
ALTER TABLE "QuantityDiscountTier" ALTER COLUMN "updatedAt" DROP DEFAULT;
