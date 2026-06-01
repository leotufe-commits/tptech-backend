-- AlterTable
ALTER TABLE "SaleLine" ADD COLUMN     "manualDiscountAppliesToOverride" TEXT,
ADD COLUMN     "manualDiscountOverride" JSONB,
ADD COLUMN     "manualPriceOverride" DECIMAL(14,4),
ADD COLUMN     "manualTaxAppliesToOverride" TEXT,
ADD COLUMN     "priceListIdOverride" TEXT,
ADD COLUMN     "taxOverride" JSONB;
