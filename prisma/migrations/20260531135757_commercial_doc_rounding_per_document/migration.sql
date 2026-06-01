-- CreateEnum
CREATE TYPE "CommercialRoundingScope" AS ENUM ('PER_LINE_LEGACY', 'PER_DOCUMENT');

-- AlterTable
ALTER TABLE "PriceList" ADD COLUMN     "commercialRoundingScope" "CommercialRoundingScope" NOT NULL DEFAULT 'PER_LINE_LEGACY';

-- AlterTable
ALTER TABLE "Sale" ADD COLUMN     "commercialDocumentRoundingSnapshot" JSONB;
