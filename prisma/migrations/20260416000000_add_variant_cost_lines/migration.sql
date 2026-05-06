-- Permite que las variantes tengan su propia composición de costo (ArticleCostLine).
-- variantId = null → línea del artículo padre
-- variantId = id de variante → línea propia de esa variante

-- AlterTable
ALTER TABLE "ArticleCostLine" ADD COLUMN "variantId" TEXT;

-- CreateIndex
CREATE INDEX "ArticleCostLine_variantId_idx" ON "ArticleCostLine"("variantId");

-- AddForeignKey
ALTER TABLE "ArticleCostLine" ADD CONSTRAINT "ArticleCostLine_variantId_fkey"
  FOREIGN KEY ("variantId") REFERENCES "ArticleVariant"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
