-- CreateEnum
CREATE TYPE "VariantPricingMode" AS ENUM ('AUTO', 'OVERRIDE');

-- AlterTable
ALTER TABLE "MetalVariant" ADD COLUMN     "buyFactor" DECIMAL(12,6) NOT NULL DEFAULT 1.0,
ADD COLUMN     "pricingMode" "VariantPricingMode" NOT NULL DEFAULT 'AUTO',
ADD COLUMN     "purchasePriceOverride" DECIMAL(18,6),
ADD COLUMN     "saleFactor" DECIMAL(12,6) NOT NULL DEFAULT 1.0,
ADD COLUMN     "salePriceOverride" DECIMAL(18,6);
