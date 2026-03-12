-- CreateEnum
CREATE TYPE "CategoryAttributeInputType" AS ENUM ('TEXT', 'TEXTAREA', 'NUMBER', 'DECIMAL', 'BOOLEAN', 'DATE', 'SELECT', 'MULTISELECT', 'COLOR');

-- AlterTable
ALTER TABLE "ArticleCategory" ADD COLUMN     "defaultPriceListId" TEXT;

-- CreateTable
CREATE TABLE "ArticleCategoryAttribute" (
    "id" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "categoryId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "code" TEXT NOT NULL DEFAULT '',
    "inputType" "CategoryAttributeInputType" NOT NULL,
    "isRequired" BOOLEAN NOT NULL DEFAULT false,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "isFilterable" BOOLEAN NOT NULL DEFAULT true,
    "isVariantAxis" BOOLEAN NOT NULL DEFAULT false,
    "inheritToChild" BOOLEAN NOT NULL DEFAULT true,
    "sortOrder" INTEGER NOT NULL DEFAULT 0,
    "helpText" TEXT NOT NULL DEFAULT '',
    "defaultValue" TEXT NOT NULL DEFAULT '',
    "unit" TEXT NOT NULL DEFAULT '',
    "deletedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ArticleCategoryAttribute_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ArticleCategoryAttributeOption" (
    "id" TEXT NOT NULL,
    "attributeId" TEXT NOT NULL,
    "label" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "colorHex" TEXT NOT NULL DEFAULT '',
    "sortOrder" INTEGER NOT NULL DEFAULT 0,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ArticleCategoryAttributeOption_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ArticleCategoryAttribute_jewelryId_idx" ON "ArticleCategoryAttribute"("jewelryId");

-- CreateIndex
CREATE INDEX "ArticleCategoryAttribute_categoryId_idx" ON "ArticleCategoryAttribute"("categoryId");

-- CreateIndex
CREATE INDEX "ArticleCategoryAttribute_categoryId_isActive_idx" ON "ArticleCategoryAttribute"("categoryId", "isActive");

-- CreateIndex
CREATE INDEX "ArticleCategoryAttribute_deletedAt_idx" ON "ArticleCategoryAttribute"("deletedAt");

-- CreateIndex
CREATE INDEX "ArticleCategoryAttributeOption_attributeId_idx" ON "ArticleCategoryAttributeOption"("attributeId");

-- CreateIndex
CREATE INDEX "ArticleCategoryAttributeOption_attributeId_isActive_idx" ON "ArticleCategoryAttributeOption"("attributeId", "isActive");

-- CreateIndex
CREATE INDEX "ArticleCategory_defaultPriceListId_idx" ON "ArticleCategory"("defaultPriceListId");

-- AddForeignKey
ALTER TABLE "ArticleCategory" ADD CONSTRAINT "ArticleCategory_defaultPriceListId_fkey" FOREIGN KEY ("defaultPriceListId") REFERENCES "PriceList"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ArticleCategoryAttribute" ADD CONSTRAINT "ArticleCategoryAttribute_categoryId_fkey" FOREIGN KEY ("categoryId") REFERENCES "ArticleCategory"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ArticleCategoryAttributeOption" ADD CONSTRAINT "ArticleCategoryAttributeOption_attributeId_fkey" FOREIGN KEY ("attributeId") REFERENCES "ArticleCategoryAttribute"("id") ON DELETE CASCADE ON UPDATE CASCADE;
