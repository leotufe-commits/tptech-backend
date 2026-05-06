-- AlterTable
ALTER TABLE "PurchaseLine" ADD COLUMN     "pricingSnapshot" JSONB;

-- AlterTable
ALTER TABLE "SaleLine" ADD COLUMN     "pricingSnapshot" JSONB;
