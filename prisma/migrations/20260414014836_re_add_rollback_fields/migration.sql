-- AlterTable
ALTER TABLE "ArticleMovementLine" ADD COLUMN     "totalWeight" DECIMAL(14,4),
ADD COLUMN     "weightPerUnit" DECIMAL(10,4);

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "themePreference" TEXT;

-- AlterTable
ALTER TABLE "Warehouse" ADD COLUMN     "apartment" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "email" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "floor" TEXT NOT NULL DEFAULT '';

-- CreateTable
CREATE TABLE "WarehouseAttachment" (
    "id" TEXT NOT NULL,
    "warehouseId" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "filename" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "mimeType" TEXT NOT NULL DEFAULT '',
    "size" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "deletedAt" TIMESTAMP(3),

    CONSTRAINT "WarehouseAttachment_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "WarehouseAttachment_warehouseId_idx" ON "WarehouseAttachment"("warehouseId");

-- CreateIndex
CREATE INDEX "WarehouseAttachment_jewelryId_idx" ON "WarehouseAttachment"("jewelryId");

-- CreateIndex
CREATE INDEX "WarehouseAttachment_deletedAt_idx" ON "WarehouseAttachment"("deletedAt");

-- AddForeignKey
ALTER TABLE "WarehouseAttachment" ADD CONSTRAINT "WarehouseAttachment_warehouseId_fkey" FOREIGN KEY ("warehouseId") REFERENCES "Warehouse"("id") ON DELETE CASCADE ON UPDATE CASCADE;
