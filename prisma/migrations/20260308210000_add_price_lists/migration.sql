-- CreateEnum
CREATE TYPE "PriceListScope" AS ENUM ('GENERAL', 'CHANNEL', 'CATEGORY', 'CLIENT');
CREATE TYPE "PriceListMode" AS ENUM ('MARGIN_TOTAL', 'METAL_HECHURA', 'COST_PER_GRAM');
CREATE TYPE "RoundingTarget" AS ENUM ('NONE', 'METAL', 'FINAL_PRICE');
CREATE TYPE "RoundingMode" AS ENUM ('NONE', 'INTEGER', 'DECIMAL_1', 'DECIMAL_2', 'TEN', 'HUNDRED');
CREATE TYPE "RoundingDirection" AS ENUM ('NEAREST', 'UP', 'DOWN');

-- CreateTable
CREATE TABLE "PriceList" (
    "id" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "code" TEXT NOT NULL DEFAULT '',
    "description" TEXT NOT NULL DEFAULT '',
    "scope" "PriceListScope" NOT NULL DEFAULT 'GENERAL',
    "categoryId" TEXT,
    "channelId" TEXT,
    "clientId" TEXT,
    "mode" "PriceListMode" NOT NULL DEFAULT 'MARGIN_TOTAL',
    "marginTotal" DECIMAL(10,4),
    "marginMetal" DECIMAL(10,4),
    "marginHechura" DECIMAL(10,4),
    "costPerGram" DECIMAL(18,6),
    "surcharge" DECIMAL(10,4),
    "minimumPrice" DECIMAL(18,2),
    "roundingTarget" "RoundingTarget" NOT NULL DEFAULT 'NONE',
    "roundingMode" "RoundingMode" NOT NULL DEFAULT 'NONE',
    "roundingDirection" "RoundingDirection" NOT NULL DEFAULT 'NEAREST',
    "validFrom" TIMESTAMP(3),
    "validTo" TIMESTAMP(3),
    "isFavorite" BOOLEAN NOT NULL DEFAULT false,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "sortOrder" INTEGER NOT NULL DEFAULT 0,
    "notes" TEXT NOT NULL DEFAULT '',
    "deletedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "PriceList_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "PriceList_jewelryId_idx" ON "PriceList"("jewelryId");
CREATE INDEX "PriceList_jewelryId_isActive_idx" ON "PriceList"("jewelryId", "isActive");
CREATE INDEX "PriceList_jewelryId_isFavorite_idx" ON "PriceList"("jewelryId", "isFavorite");
CREATE INDEX "PriceList_jewelryId_scope_idx" ON "PriceList"("jewelryId", "scope");
CREATE INDEX "PriceList_categoryId_idx" ON "PriceList"("categoryId");
CREATE INDEX "PriceList_jewelryId_deletedAt_idx" ON "PriceList"("jewelryId", "deletedAt");
CREATE INDEX "PriceList_deletedAt_idx" ON "PriceList"("deletedAt");

-- AddForeignKey
ALTER TABLE "PriceList" ADD CONSTRAINT "PriceList_jewelryId_fkey" FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "PriceList" ADD CONSTRAINT "PriceList_categoryId_fkey" FOREIGN KEY ("categoryId") REFERENCES "ArticleCategory"("id") ON DELETE SET NULL ON UPDATE CASCADE;
