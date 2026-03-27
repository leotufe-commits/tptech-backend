-- AlterTable
ALTER TABLE "ArticleCostLine" ADD COLUMN "catalogItemId" TEXT;

-- AddForeignKey
ALTER TABLE "ArticleCostLine" ADD CONSTRAINT "ArticleCostLine_catalogItemId_fkey" FOREIGN KEY ("catalogItemId") REFERENCES "Article"("id") ON DELETE SET NULL ON UPDATE CASCADE;
