-- AlterTable
ALTER TABLE "Purchase" ADD COLUMN     "currencyId" TEXT,
ADD COLUMN     "currencySnapshot" JSONB,
ADD COLUMN     "issuerSnapshot" JSONB;

-- AlterTable
ALTER TABLE "Sale" ADD COLUMN     "currencyId" TEXT,
ADD COLUMN     "currencySnapshot" JSONB,
ADD COLUMN     "issuerSnapshot" JSONB,
ADD COLUMN     "sellerSnapshot" JSONB;
