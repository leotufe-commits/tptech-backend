-- CreateEnum
CREATE TYPE "CommissionType" AS ENUM ('NONE', 'PERCENTAGE', 'FIXED_AMOUNT');

-- CreateTable
CREATE TABLE "Seller" (
    "id" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "firstName" TEXT NOT NULL,
    "lastName" TEXT NOT NULL,
    "displayName" TEXT NOT NULL DEFAULT '',
    "documentType" TEXT NOT NULL DEFAULT '',
    "documentNumber" TEXT NOT NULL DEFAULT '',
    "email" TEXT NOT NULL DEFAULT '',
    "phone" TEXT NOT NULL DEFAULT '',
    "commissionType" "CommissionType" NOT NULL DEFAULT 'NONE',
    "commissionValue" DECIMAL(10,4),
    "userId" TEXT,
    "isFavorite" BOOLEAN NOT NULL DEFAULT false,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "sortOrder" INTEGER NOT NULL DEFAULT 0,
    "notes" TEXT NOT NULL DEFAULT '',
    "deletedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Seller_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SellerWarehouse" (
    "sellerId" TEXT NOT NULL,
    "warehouseId" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,

    CONSTRAINT "SellerWarehouse_pkey" PRIMARY KEY ("sellerId","warehouseId")
);

-- CreateIndex
CREATE INDEX "Seller_jewelryId_idx" ON "Seller"("jewelryId");
CREATE INDEX "Seller_jewelryId_isActive_idx" ON "Seller"("jewelryId", "isActive");
CREATE INDEX "Seller_jewelryId_isFavorite_idx" ON "Seller"("jewelryId", "isFavorite");
CREATE INDEX "Seller_jewelryId_deletedAt_idx" ON "Seller"("jewelryId", "deletedAt");
CREATE INDEX "Seller_deletedAt_idx" ON "Seller"("deletedAt");
CREATE INDEX "SellerWarehouse_sellerId_idx" ON "SellerWarehouse"("sellerId");
CREATE INDEX "SellerWarehouse_warehouseId_idx" ON "SellerWarehouse"("warehouseId");
CREATE INDEX "SellerWarehouse_jewelryId_idx" ON "SellerWarehouse"("jewelryId");

-- AddForeignKey
ALTER TABLE "Seller" ADD CONSTRAINT "Seller_jewelryId_fkey" FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SellerWarehouse" ADD CONSTRAINT "SellerWarehouse_sellerId_fkey" FOREIGN KEY ("sellerId") REFERENCES "Seller"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SellerWarehouse" ADD CONSTRAINT "SellerWarehouse_warehouseId_fkey" FOREIGN KEY ("warehouseId") REFERENCES "Warehouse"("id") ON DELETE CASCADE ON UPDATE CASCADE;
