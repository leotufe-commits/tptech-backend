-- DropIndex
DROP INDEX "Warehouse_jewelryId_isActive_idx";

-- DropIndex
DROP INDEX "Warehouse_jewelryId_name_key";

-- CreateIndex
CREATE INDEX "Warehouse_jewelryId_deletedAt_idx" ON "Warehouse"("jewelryId", "deletedAt");
