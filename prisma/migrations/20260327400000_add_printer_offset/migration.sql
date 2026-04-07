-- AlterTable
ALTER TABLE "LabelElement" ALTER COLUMN "updatedAt" DROP DEFAULT;

-- AlterTable
ALTER TABLE "LabelTemplate" ALTER COLUMN "updatedAt" DROP DEFAULT;

-- AlterTable
ALTER TABLE "PrinterProfile" ADD COLUMN     "offsetXMm" DECIMAL(8,2) NOT NULL DEFAULT 0,
ADD COLUMN     "offsetYMm" DECIMAL(8,2) NOT NULL DEFAULT 0,
ALTER COLUMN "updatedAt" DROP DEFAULT;

-- AlterTable
ALTER TABLE "QuantityDiscountTier" ALTER COLUMN "updatedAt" DROP DEFAULT;
