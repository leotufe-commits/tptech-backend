-- AlterEnum
ALTER TYPE "CouponScope" ADD VALUE 'BRAND';

-- CreateTable
CREATE TABLE "CouponBrand" (
    "id" TEXT NOT NULL,
    "couponId" TEXT NOT NULL,
    "brandName" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,

    CONSTRAINT "CouponBrand_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "CouponBrand_couponId_idx" ON "CouponBrand"("couponId");

-- CreateIndex
CREATE INDEX "CouponBrand_jewelryId_idx" ON "CouponBrand"("jewelryId");

-- CreateIndex
CREATE UNIQUE INDEX "CouponBrand_couponId_brandName_key" ON "CouponBrand"("couponId", "brandName");

-- AddForeignKey
ALTER TABLE "CouponBrand" ADD CONSTRAINT "CouponBrand_couponId_fkey" FOREIGN KEY ("couponId") REFERENCES "Coupon"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CouponBrand" ADD CONSTRAINT "CouponBrand_jewelryId_fkey" FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;
