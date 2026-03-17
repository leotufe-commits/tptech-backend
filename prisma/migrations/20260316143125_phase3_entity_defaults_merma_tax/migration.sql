-- AlterTable
ALTER TABLE "ArticleCategory" ADD COLUMN     "mermaPercent" DECIMAL(5,2);

-- AlterTable
ALTER TABLE "CommercialEntity" ADD COLUMN     "currencyId" TEXT,
ADD COLUMN     "priceListId" TEXT;

-- AlterTable
ALTER TABLE "Jewelry" ADD COLUMN     "defaultMermaPercent" DECIMAL(5,2);

-- AlterTable
ALTER TABLE "Tax" ADD COLUMN     "allowDocumentOverride" BOOLEAN NOT NULL DEFAULT false;

-- CreateIndex
CREATE INDEX "CommercialEntity_priceListId_idx" ON "CommercialEntity"("priceListId");

-- CreateIndex
CREATE INDEX "CommercialEntity_currencyId_idx" ON "CommercialEntity"("currencyId");

-- AddForeignKey
ALTER TABLE "CommercialEntity" ADD CONSTRAINT "CommercialEntity_priceListId_fkey" FOREIGN KEY ("priceListId") REFERENCES "PriceList"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CommercialEntity" ADD CONSTRAINT "CommercialEntity_currencyId_fkey" FOREIGN KEY ("currencyId") REFERENCES "Currency"("id") ON DELETE SET NULL ON UPDATE CASCADE;
