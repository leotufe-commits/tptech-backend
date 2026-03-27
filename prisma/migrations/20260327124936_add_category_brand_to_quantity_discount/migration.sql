-- AlterTable
ALTER TABLE "QuantityDiscount" ADD COLUMN     "brand" TEXT,
ADD COLUMN     "categoryId" TEXT;

-- CreateIndex
CREATE INDEX "QuantityDiscount_categoryId_idx" ON "QuantityDiscount"("categoryId");

-- AddForeignKey
ALTER TABLE "QuantityDiscount" ADD CONSTRAINT "QuantityDiscount_categoryId_fkey" FOREIGN KEY ("categoryId") REFERENCES "ArticleCategory"("id") ON DELETE SET NULL ON UPDATE CASCADE;
