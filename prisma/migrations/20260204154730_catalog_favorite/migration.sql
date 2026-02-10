-- AlterEnum
ALTER TYPE "CatalogType" ADD VALUE 'DOCUMENT_TYPE';

-- AlterTable
ALTER TABLE "CatalogItem" ADD COLUMN     "isFavorite" BOOLEAN NOT NULL DEFAULT false;

-- CreateIndex
CREATE INDEX "CatalogItem_jewelryId_type_isFavorite_idx" ON "CatalogItem"("jewelryId", "type", "isFavorite");
