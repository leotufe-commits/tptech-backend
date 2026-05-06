-- CreateEnum
CREATE TYPE "CouponDiscountType" AS ENUM ('PERCENTAGE', 'FIXED_AMOUNT');

-- CreateEnum
CREATE TYPE "CouponScope" AS ENUM ('ALL', 'CLIENT', 'CATEGORY', 'ARTICLE', 'GROUP');

-- AlterTable
ALTER TABLE "Sale" ADD COLUMN     "couponId" TEXT,
ADD COLUMN     "couponSnapshot" JSONB;

-- CreateTable
CREATE TABLE "Coupon" (
    "id" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "code" TEXT NOT NULL,
    "description" TEXT NOT NULL DEFAULT '',
    "discountType" "CouponDiscountType" NOT NULL,
    "discountValue" DECIMAL(14,4) NOT NULL,
    "validFrom" TIMESTAMP(3),
    "validTo" TIMESTAMP(3),
    "maxUsesTotal" INTEGER,
    "maxUsesPerClient" INTEGER,
    "applyScope" "CouponScope" NOT NULL DEFAULT 'ALL',
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "notes" TEXT NOT NULL DEFAULT '',
    "deletedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Coupon_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CouponRedemption" (
    "id" TEXT NOT NULL,
    "couponId" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "saleId" TEXT,
    "clientId" TEXT,
    "amount" DECIMAL(14,4) NOT NULL,
    "redeemedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CouponRedemption_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CouponArticle" (
    "id" TEXT NOT NULL,
    "couponId" TEXT NOT NULL,
    "articleId" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,

    CONSTRAINT "CouponArticle_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CouponCategory" (
    "id" TEXT NOT NULL,
    "couponId" TEXT NOT NULL,
    "categoryId" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,

    CONSTRAINT "CouponCategory_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CouponGroup" (
    "id" TEXT NOT NULL,
    "couponId" TEXT NOT NULL,
    "groupId" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,

    CONSTRAINT "CouponGroup_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CouponClient" (
    "id" TEXT NOT NULL,
    "couponId" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,

    CONSTRAINT "CouponClient_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "Coupon_jewelryId_idx" ON "Coupon"("jewelryId");

-- CreateIndex
CREATE INDEX "Coupon_jewelryId_isActive_idx" ON "Coupon"("jewelryId", "isActive");

-- CreateIndex
CREATE INDEX "Coupon_jewelryId_deletedAt_idx" ON "Coupon"("jewelryId", "deletedAt");

-- CreateIndex
CREATE UNIQUE INDEX "Coupon_jewelryId_code_key" ON "Coupon"("jewelryId", "code");

-- CreateIndex
CREATE INDEX "CouponRedemption_couponId_idx" ON "CouponRedemption"("couponId");

-- CreateIndex
CREATE INDEX "CouponRedemption_saleId_idx" ON "CouponRedemption"("saleId");

-- CreateIndex
CREATE INDEX "CouponRedemption_clientId_idx" ON "CouponRedemption"("clientId");

-- CreateIndex
CREATE INDEX "CouponRedemption_jewelryId_idx" ON "CouponRedemption"("jewelryId");

-- CreateIndex
CREATE INDEX "CouponArticle_couponId_idx" ON "CouponArticle"("couponId");

-- CreateIndex
CREATE INDEX "CouponArticle_articleId_idx" ON "CouponArticle"("articleId");

-- CreateIndex
CREATE INDEX "CouponArticle_jewelryId_idx" ON "CouponArticle"("jewelryId");

-- CreateIndex
CREATE UNIQUE INDEX "CouponArticle_couponId_articleId_key" ON "CouponArticle"("couponId", "articleId");

-- CreateIndex
CREATE INDEX "CouponCategory_couponId_idx" ON "CouponCategory"("couponId");

-- CreateIndex
CREATE INDEX "CouponCategory_categoryId_idx" ON "CouponCategory"("categoryId");

-- CreateIndex
CREATE INDEX "CouponCategory_jewelryId_idx" ON "CouponCategory"("jewelryId");

-- CreateIndex
CREATE UNIQUE INDEX "CouponCategory_couponId_categoryId_key" ON "CouponCategory"("couponId", "categoryId");

-- CreateIndex
CREATE INDEX "CouponGroup_couponId_idx" ON "CouponGroup"("couponId");

-- CreateIndex
CREATE INDEX "CouponGroup_groupId_idx" ON "CouponGroup"("groupId");

-- CreateIndex
CREATE INDEX "CouponGroup_jewelryId_idx" ON "CouponGroup"("jewelryId");

-- CreateIndex
CREATE UNIQUE INDEX "CouponGroup_couponId_groupId_key" ON "CouponGroup"("couponId", "groupId");

-- CreateIndex
CREATE INDEX "CouponClient_couponId_idx" ON "CouponClient"("couponId");

-- CreateIndex
CREATE INDEX "CouponClient_clientId_idx" ON "CouponClient"("clientId");

-- CreateIndex
CREATE INDEX "CouponClient_jewelryId_idx" ON "CouponClient"("jewelryId");

-- CreateIndex
CREATE UNIQUE INDEX "CouponClient_couponId_clientId_key" ON "CouponClient"("couponId", "clientId");

-- CreateIndex
CREATE INDEX "Sale_couponId_idx" ON "Sale"("couponId");

-- AddForeignKey
ALTER TABLE "Sale" ADD CONSTRAINT "Sale_couponId_fkey" FOREIGN KEY ("couponId") REFERENCES "Coupon"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Coupon" ADD CONSTRAINT "Coupon_jewelryId_fkey" FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CouponRedemption" ADD CONSTRAINT "CouponRedemption_couponId_fkey" FOREIGN KEY ("couponId") REFERENCES "Coupon"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CouponRedemption" ADD CONSTRAINT "CouponRedemption_saleId_fkey" FOREIGN KEY ("saleId") REFERENCES "Sale"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CouponRedemption" ADD CONSTRAINT "CouponRedemption_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "CommercialEntity"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CouponArticle" ADD CONSTRAINT "CouponArticle_couponId_fkey" FOREIGN KEY ("couponId") REFERENCES "Coupon"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CouponArticle" ADD CONSTRAINT "CouponArticle_articleId_fkey" FOREIGN KEY ("articleId") REFERENCES "Article"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CouponCategory" ADD CONSTRAINT "CouponCategory_couponId_fkey" FOREIGN KEY ("couponId") REFERENCES "Coupon"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CouponCategory" ADD CONSTRAINT "CouponCategory_categoryId_fkey" FOREIGN KEY ("categoryId") REFERENCES "ArticleCategory"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CouponGroup" ADD CONSTRAINT "CouponGroup_couponId_fkey" FOREIGN KEY ("couponId") REFERENCES "Coupon"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CouponGroup" ADD CONSTRAINT "CouponGroup_groupId_fkey" FOREIGN KEY ("groupId") REFERENCES "ArticleGroup"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CouponClient" ADD CONSTRAINT "CouponClient_couponId_fkey" FOREIGN KEY ("couponId") REFERENCES "Coupon"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CouponClient" ADD CONSTRAINT "CouponClient_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "CommercialEntity"("id") ON DELETE CASCADE ON UPDATE CASCADE;
