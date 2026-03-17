-- CreateEnum
CREATE TYPE "ShippingCarrierType" AS ENUM ('DELIVERY', 'PICKUP');

-- AlterTable
ALTER TABLE "ArticleAttributeDef" ALTER COLUMN "updatedAt" DROP DEFAULT;

-- AlterTable
ALTER TABLE "ArticleAttributeDefOption" ALTER COLUMN "updatedAt" DROP DEFAULT;

-- AlterTable
ALTER TABLE "ShippingCarrier" ADD COLUMN     "provider" TEXT,
ADD COLUMN     "providerConfig" JSONB,
ADD COLUMN     "type" "ShippingCarrierType" NOT NULL DEFAULT 'DELIVERY';

-- CreateIndex
CREATE INDEX "ShippingCarrier_jewelryId_type_idx" ON "ShippingCarrier"("jewelryId", "type");
