-- CreateEnum
CREATE TYPE "ArticleStatus" AS ENUM ('DRAFT', 'ACTIVE', 'DISCONTINUED', 'ARCHIVED');

-- CreateEnum
CREATE TYPE "StockMode" AS ENUM ('NO_STOCK', 'BY_ARTICLE', 'BY_MATERIAL');

-- CreateEnum
CREATE TYPE "HechuraPriceMode" AS ENUM ('FIXED', 'PER_GRAM');

-- CreateTable
CREATE TABLE "Article" (
    "id" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "code" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT NOT NULL DEFAULT '',
    "categoryId" TEXT,
    "status" "ArticleStatus" NOT NULL DEFAULT 'DRAFT',
    "stockMode" "StockMode" NOT NULL DEFAULT 'NO_STOCK',
    "hechuraPrice" DECIMAL(14,4),
    "hechuraPriceMode" "HechuraPriceMode" NOT NULL DEFAULT 'FIXED',
    "mermaPercent" DECIMAL(5,2),
    "mainImageUrl" TEXT NOT NULL DEFAULT '',
    "isFavorite" BOOLEAN NOT NULL DEFAULT false,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "notes" TEXT NOT NULL DEFAULT '',
    "deletedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Article_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ArticleMetalComposition" (
    "id" TEXT NOT NULL,
    "articleId" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "variantId" TEXT NOT NULL,
    "grams" DECIMAL(10,4) NOT NULL,
    "isBase" BOOLEAN NOT NULL DEFAULT false,
    "sortOrder" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ArticleMetalComposition_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ArticleVariant" (
    "id" TEXT NOT NULL,
    "articleId" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "code" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "weightOverride" DECIMAL(10,4),
    "hechuraPriceOverride" DECIMAL(14,4),
    "priceOverride" DECIMAL(14,4),
    "imageUrl" TEXT NOT NULL DEFAULT '',
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "sortOrder" INTEGER NOT NULL DEFAULT 0,
    "deletedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ArticleVariant_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ArticleAttributeValue" (
    "id" TEXT NOT NULL,
    "articleId" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "assignmentId" TEXT NOT NULL,
    "value" TEXT NOT NULL DEFAULT '',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ArticleAttributeValue_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ArticleImage" (
    "id" TEXT NOT NULL,
    "articleId" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "label" TEXT NOT NULL DEFAULT '',
    "isMain" BOOLEAN NOT NULL DEFAULT false,
    "sortOrder" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ArticleImage_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ArticleStock" (
    "id" TEXT NOT NULL,
    "articleId" TEXT NOT NULL,
    "variantId" TEXT,
    "warehouseId" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "quantity" DECIMAL(14,4) NOT NULL DEFAULT 0,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ArticleStock_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "Article_jewelryId_idx" ON "Article"("jewelryId");

-- CreateIndex
CREATE INDEX "Article_categoryId_idx" ON "Article"("categoryId");

-- CreateIndex
CREATE INDEX "Article_jewelryId_status_idx" ON "Article"("jewelryId", "status");

-- CreateIndex
CREATE INDEX "Article_jewelryId_isActive_idx" ON "Article"("jewelryId", "isActive");

-- CreateIndex
CREATE INDEX "Article_deletedAt_idx" ON "Article"("deletedAt");

-- CreateIndex
CREATE UNIQUE INDEX "Article_jewelryId_code_key" ON "Article"("jewelryId", "code");

-- CreateIndex
CREATE INDEX "ArticleMetalComposition_articleId_idx" ON "ArticleMetalComposition"("articleId");

-- CreateIndex
CREATE INDEX "ArticleMetalComposition_jewelryId_idx" ON "ArticleMetalComposition"("jewelryId");

-- CreateIndex
CREATE UNIQUE INDEX "ArticleMetalComposition_articleId_variantId_key" ON "ArticleMetalComposition"("articleId", "variantId");

-- CreateIndex
CREATE INDEX "ArticleVariant_articleId_idx" ON "ArticleVariant"("articleId");

-- CreateIndex
CREATE INDEX "ArticleVariant_jewelryId_idx" ON "ArticleVariant"("jewelryId");

-- CreateIndex
CREATE UNIQUE INDEX "ArticleVariant_articleId_code_key" ON "ArticleVariant"("articleId", "code");

-- CreateIndex
CREATE INDEX "ArticleAttributeValue_articleId_idx" ON "ArticleAttributeValue"("articleId");

-- CreateIndex
CREATE INDEX "ArticleAttributeValue_assignmentId_idx" ON "ArticleAttributeValue"("assignmentId");

-- CreateIndex
CREATE UNIQUE INDEX "ArticleAttributeValue_articleId_assignmentId_key" ON "ArticleAttributeValue"("articleId", "assignmentId");

-- CreateIndex
CREATE INDEX "ArticleImage_articleId_idx" ON "ArticleImage"("articleId");

-- CreateIndex
CREATE INDEX "ArticleImage_jewelryId_idx" ON "ArticleImage"("jewelryId");

-- CreateIndex
CREATE INDEX "ArticleStock_articleId_idx" ON "ArticleStock"("articleId");

-- CreateIndex
CREATE INDEX "ArticleStock_jewelryId_idx" ON "ArticleStock"("jewelryId");

-- CreateIndex
CREATE INDEX "ArticleStock_warehouseId_idx" ON "ArticleStock"("warehouseId");

-- CreateIndex
CREATE UNIQUE INDEX "ArticleStock_jewelryId_warehouseId_articleId_variantId_key" ON "ArticleStock"("jewelryId", "warehouseId", "articleId", "variantId");

-- AddForeignKey
ALTER TABLE "Article" ADD CONSTRAINT "Article_jewelryId_fkey" FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Article" ADD CONSTRAINT "Article_categoryId_fkey" FOREIGN KEY ("categoryId") REFERENCES "ArticleCategory"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ArticleMetalComposition" ADD CONSTRAINT "ArticleMetalComposition_articleId_fkey" FOREIGN KEY ("articleId") REFERENCES "Article"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ArticleMetalComposition" ADD CONSTRAINT "ArticleMetalComposition_variantId_fkey" FOREIGN KEY ("variantId") REFERENCES "MetalVariant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ArticleVariant" ADD CONSTRAINT "ArticleVariant_articleId_fkey" FOREIGN KEY ("articleId") REFERENCES "Article"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ArticleAttributeValue" ADD CONSTRAINT "ArticleAttributeValue_articleId_fkey" FOREIGN KEY ("articleId") REFERENCES "Article"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ArticleAttributeValue" ADD CONSTRAINT "ArticleAttributeValue_assignmentId_fkey" FOREIGN KEY ("assignmentId") REFERENCES "ArticleCategoryAttribute"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ArticleImage" ADD CONSTRAINT "ArticleImage_articleId_fkey" FOREIGN KEY ("articleId") REFERENCES "Article"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ArticleStock" ADD CONSTRAINT "ArticleStock_articleId_fkey" FOREIGN KEY ("articleId") REFERENCES "Article"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ArticleStock" ADD CONSTRAINT "ArticleStock_variantId_fkey" FOREIGN KEY ("variantId") REFERENCES "ArticleVariant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ArticleStock" ADD CONSTRAINT "ArticleStock_warehouseId_fkey" FOREIGN KEY ("warehouseId") REFERENCES "Warehouse"("id") ON DELETE CASCADE ON UPDATE CASCADE;
