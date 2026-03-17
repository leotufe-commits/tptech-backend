-- CreateEnum
CREATE TYPE "ShippingCarrierType" AS ENUM ('DELIVERY', 'PICKUP');

-- AlterTable
ALTER TABLE "ShippingCarrier" ADD COLUMN     "provider" TEXT,
ADD COLUMN     "providerConfig" JSONB,
ADD COLUMN     "type" "ShippingCarrierType" NOT NULL DEFAULT 'DELIVERY',
ADD COLUMN     "warehouseId" TEXT;

-- CreateIndex
CREATE INDEX "ShippingCarrier_jewelryId_type_idx" ON "ShippingCarrier"("jewelryId", "type");

-- CreateIndex
CREATE INDEX "ShippingCarrier_warehouseId_idx" ON "ShippingCarrier"("warehouseId");

-- AddForeignKey
ALTER TABLE "ShippingCarrier" ADD CONSTRAINT "ShippingCarrier_warehouseId_fkey" FOREIGN KEY ("warehouseId") REFERENCES "Warehouse"("id") ON DELETE SET NULL ON UPDATE CASCADE;
