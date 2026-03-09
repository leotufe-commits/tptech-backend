-- CreateEnum
CREATE TYPE "ShippingCalcMode" AS ENUM ('FIXED', 'BY_WEIGHT', 'BY_ZONE');

-- CreateTable
CREATE TABLE "ShippingCarrier" (
    "id" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "code" TEXT NOT NULL DEFAULT '',
    "logoUrl" TEXT NOT NULL DEFAULT '',
    "trackingUrl" TEXT NOT NULL DEFAULT '',
    "freeShippingThreshold" DECIMAL(18,2),
    "isFavorite" BOOLEAN NOT NULL DEFAULT false,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "sortOrder" INTEGER NOT NULL DEFAULT 0,
    "notes" TEXT NOT NULL DEFAULT '',
    "deletedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ShippingCarrier_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ShippingRate" (
    "id" TEXT NOT NULL,
    "carrierId" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "zone" TEXT NOT NULL DEFAULT '',
    "calculationMode" "ShippingCalcMode" NOT NULL DEFAULT 'FIXED',
    "fixedPrice" DECIMAL(18,2),
    "pricePerKg" DECIMAL(18,4),
    "minWeight" DECIMAL(10,3),
    "maxWeight" DECIMAL(10,3),
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "sortOrder" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ShippingRate_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ShippingCarrier_jewelryId_idx" ON "ShippingCarrier"("jewelryId");
CREATE INDEX "ShippingCarrier_jewelryId_isActive_idx" ON "ShippingCarrier"("jewelryId", "isActive");
CREATE INDEX "ShippingCarrier_jewelryId_isFavorite_idx" ON "ShippingCarrier"("jewelryId", "isFavorite");
CREATE INDEX "ShippingCarrier_jewelryId_deletedAt_idx" ON "ShippingCarrier"("jewelryId", "deletedAt");
CREATE INDEX "ShippingCarrier_deletedAt_idx" ON "ShippingCarrier"("deletedAt");
CREATE INDEX "ShippingRate_carrierId_idx" ON "ShippingRate"("carrierId");
CREATE INDEX "ShippingRate_jewelryId_idx" ON "ShippingRate"("jewelryId");

-- AddForeignKey
ALTER TABLE "ShippingCarrier" ADD CONSTRAINT "ShippingCarrier_jewelryId_fkey" FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ShippingRate" ADD CONSTRAINT "ShippingRate_carrierId_fkey" FOREIGN KEY ("carrierId") REFERENCES "ShippingCarrier"("id") ON DELETE CASCADE ON UPDATE CASCADE;
