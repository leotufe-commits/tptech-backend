-- AlterTable
ALTER TABLE "DocumentTemplate" ALTER COLUMN "headerLogoSize" SET DEFAULT '18';

-- CreateTable
CREATE TABLE "CouponVariant" (
    "id" TEXT NOT NULL,
    "couponId" TEXT NOT NULL,
    "variantId" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,

    CONSTRAINT "CouponVariant_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "CouponVariant_couponId_idx" ON "CouponVariant"("couponId");

-- CreateIndex
CREATE INDEX "CouponVariant_variantId_idx" ON "CouponVariant"("variantId");

-- CreateIndex
CREATE INDEX "CouponVariant_jewelryId_idx" ON "CouponVariant"("jewelryId");

-- CreateIndex
CREATE UNIQUE INDEX "CouponVariant_couponId_variantId_key" ON "CouponVariant"("couponId", "variantId");

-- AddForeignKey
ALTER TABLE "CouponVariant" ADD CONSTRAINT "CouponVariant_couponId_fkey" FOREIGN KEY ("couponId") REFERENCES "Coupon"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CouponVariant" ADD CONSTRAINT "CouponVariant_variantId_fkey" FOREIGN KEY ("variantId") REFERENCES "ArticleVariant"("id") ON DELETE CASCADE ON UPDATE CASCADE;
