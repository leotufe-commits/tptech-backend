-- CreateEnum
CREATE TYPE "CatalogType" AS ENUM ('IVA_CONDITION', 'PHONE_PREFIX', 'CITY', 'PROVINCE', 'COUNTRY');

-- CreateTable
CREATE TABLE "CatalogItem" (
    "id" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "type" "CatalogType" NOT NULL,
    "label" TEXT NOT NULL,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "sortOrder" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CatalogItem_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "CatalogItem_jewelryId_idx" ON "CatalogItem"("jewelryId");

-- CreateIndex
CREATE INDEX "CatalogItem_jewelryId_type_isActive_idx" ON "CatalogItem"("jewelryId", "type", "isActive");

-- CreateIndex
CREATE UNIQUE INDEX "CatalogItem_jewelryId_type_label_key" ON "CatalogItem"("jewelryId", "type", "label");

-- AddForeignKey
ALTER TABLE "CatalogItem" ADD CONSTRAINT "CatalogItem_jewelryId_fkey" FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;
