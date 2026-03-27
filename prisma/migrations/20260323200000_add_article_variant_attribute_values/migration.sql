-- CreateTable: ArticleVariantAttributeValue
-- Permite asignar valores de atributos con isVariantAxis=true a variantes de artículo.
-- Mismo patrón que ArticleAttributeValue pero para ArticleVariant.

-- DropIndex existentes que se recrean con definición correcta
DROP INDEX IF EXISTS "Article_jewelryId_barcode_key";
DROP INDEX IF EXISTS "ArticleVariant_jewelryId_barcode_key";

-- AlterTable: estandarizar updatedAt (remover DEFAULT del nivel DB, Prisma lo maneja)
ALTER TABLE "ArticleCostLine" ALTER COLUMN "updatedAt" DROP DEFAULT;
ALTER TABLE "Promotion" ALTER COLUMN "updatedAt" DROP DEFAULT;
ALTER TABLE "QuantityDiscount" ALTER COLUMN "updatedAt" DROP DEFAULT;

-- CreateTable
CREATE TABLE "ArticleVariantAttributeValue" (
    "id" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "variantId" TEXT NOT NULL,
    "assignmentId" TEXT NOT NULL,
    "value" TEXT NOT NULL DEFAULT '',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ArticleVariantAttributeValue_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ArticleVariantAttributeValue_variantId_idx" ON "ArticleVariantAttributeValue"("variantId");
CREATE INDEX "ArticleVariantAttributeValue_assignmentId_idx" ON "ArticleVariantAttributeValue"("assignmentId");
CREATE INDEX "ArticleVariantAttributeValue_jewelryId_idx" ON "ArticleVariantAttributeValue"("jewelryId");
CREATE UNIQUE INDEX "ArticleVariantAttributeValue_variantId_assignmentId_key" ON "ArticleVariantAttributeValue"("variantId", "assignmentId");

-- Recrear índices únicos de barcode
CREATE UNIQUE INDEX "Article_jewelryId_barcode_key" ON "Article"("jewelryId", "barcode");
CREATE UNIQUE INDEX "ArticleVariant_jewelryId_barcode_key" ON "ArticleVariant"("jewelryId", "barcode");

-- AddForeignKey
ALTER TABLE "ArticleVariantAttributeValue"
    ADD CONSTRAINT "ArticleVariantAttributeValue_variantId_fkey"
    FOREIGN KEY ("variantId") REFERENCES "ArticleVariant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "ArticleVariantAttributeValue"
    ADD CONSTRAINT "ArticleVariantAttributeValue_assignmentId_fkey"
    FOREIGN KEY ("assignmentId") REFERENCES "ArticleCategoryAttribute"("id") ON DELETE CASCADE ON UPDATE CASCADE;
