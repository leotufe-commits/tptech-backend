-- AlterTable
ALTER TABLE "Warehouse" ADD COLUMN     "isFavorite" BOOLEAN NOT NULL DEFAULT false;

-- CreateIndex
CREATE INDEX "Warehouse_jewelryId_isFavorite_idx" ON "Warehouse"("jewelryId", "isFavorite");
