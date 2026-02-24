-- AlterTable
ALTER TABLE "CatalogItem" ADD COLUMN     "deletedAt" TIMESTAMP(3);

-- AlterTable
ALTER TABLE "Currency" ADD COLUMN     "deletedAt" TIMESTAMP(3);

-- AlterTable
ALTER TABLE "Jewelry" ADD COLUMN     "deletedAt" TIMESTAMP(3);

-- AlterTable
ALTER TABLE "JewelryAttachment" ADD COLUMN     "deletedAt" TIMESTAMP(3);

-- AlterTable
ALTER TABLE "Metal" ADD COLUMN     "deletedAt" TIMESTAMP(3);

-- AlterTable
ALTER TABLE "MetalVariant" ADD COLUMN     "deletedAt" TIMESTAMP(3);

-- AlterTable
ALTER TABLE "UserAttachment" ADD COLUMN     "deletedAt" TIMESTAMP(3);

-- AlterTable
ALTER TABLE "Warehouse" ADD COLUMN     "deletedAt" TIMESTAMP(3);

-- CreateIndex
CREATE INDEX "CatalogItem_deletedAt_idx" ON "CatalogItem"("deletedAt");

-- CreateIndex
CREATE INDEX "CatalogItem_jewelryId_type_deletedAt_idx" ON "CatalogItem"("jewelryId", "type", "deletedAt");

-- CreateIndex
CREATE INDEX "Currency_deletedAt_idx" ON "Currency"("deletedAt");

-- CreateIndex
CREATE INDEX "Currency_jewelryId_deletedAt_idx" ON "Currency"("jewelryId", "deletedAt");

-- CreateIndex
CREATE INDEX "Jewelry_deletedAt_idx" ON "Jewelry"("deletedAt");

-- CreateIndex
CREATE INDEX "JewelryAttachment_deletedAt_idx" ON "JewelryAttachment"("deletedAt");

-- CreateIndex
CREATE INDEX "JewelryAttachment_jewelryId_deletedAt_idx" ON "JewelryAttachment"("jewelryId", "deletedAt");

-- CreateIndex
CREATE INDEX "Metal_deletedAt_idx" ON "Metal"("deletedAt");

-- CreateIndex
CREATE INDEX "Metal_jewelryId_deletedAt_idx" ON "Metal"("jewelryId", "deletedAt");

-- CreateIndex
CREATE INDEX "MetalVariant_deletedAt_idx" ON "MetalVariant"("deletedAt");

-- CreateIndex
CREATE INDEX "MetalVariant_metalId_deletedAt_idx" ON "MetalVariant"("metalId", "deletedAt");

-- CreateIndex
CREATE INDEX "UserAttachment_deletedAt_idx" ON "UserAttachment"("deletedAt");

-- CreateIndex
CREATE INDEX "UserAttachment_userId_deletedAt_idx" ON "UserAttachment"("userId", "deletedAt");

-- CreateIndex
CREATE INDEX "Warehouse_deletedAt_idx" ON "Warehouse"("deletedAt");

-- CreateIndex
CREATE INDEX "Warehouse_jewelryId_deletedAt_idx" ON "Warehouse"("jewelryId", "deletedAt");
