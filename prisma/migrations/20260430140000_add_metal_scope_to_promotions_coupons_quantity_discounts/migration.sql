-- FASE 1 — alcance METALS para Promociones, Cupones y Descuentos por cantidad.
-- Solo schema. Servicios, pricing-engine y UI quedan intactos. Datos
-- existentes no se ven afectados (todos los campos nuevos son nullable o
-- tienen default seguro).

-- 1) Promotion: agregar valor METALS al enum.
ALTER TYPE "PromotionScope" ADD VALUE IF NOT EXISTS 'METALS';

-- 2) Coupon: agregar valor METALS al enum.
ALTER TYPE "CouponScope" ADD VALUE IF NOT EXISTS 'METALS';

-- 3) Tabla pivot Promotion <-> MetalVariant.
CREATE TABLE "PromotionMetalVariant" (
  "id"             TEXT PRIMARY KEY,
  "promotionId"    TEXT NOT NULL,
  "metalVariantId" TEXT NOT NULL,
  "jewelryId"      TEXT NOT NULL,
  CONSTRAINT "PromotionMetalVariant_promotionId_fkey"
    FOREIGN KEY ("promotionId") REFERENCES "Promotion"("id") ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "PromotionMetalVariant_metalVariantId_fkey"
    FOREIGN KEY ("metalVariantId") REFERENCES "MetalVariant"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "PromotionMetalVariant_promotionId_metalVariantId_key"
  ON "PromotionMetalVariant"("promotionId", "metalVariantId");
CREATE INDEX "PromotionMetalVariant_promotionId_idx"
  ON "PromotionMetalVariant"("promotionId");
CREATE INDEX "PromotionMetalVariant_metalVariantId_idx"
  ON "PromotionMetalVariant"("metalVariantId");
CREATE INDEX "PromotionMetalVariant_jewelryId_idx"
  ON "PromotionMetalVariant"("jewelryId");

-- 4) Tabla pivot Coupon <-> MetalVariant.
CREATE TABLE "CouponMetalVariant" (
  "id"             TEXT PRIMARY KEY,
  "couponId"       TEXT NOT NULL,
  "metalVariantId" TEXT NOT NULL,
  "jewelryId"      TEXT NOT NULL,
  CONSTRAINT "CouponMetalVariant_couponId_fkey"
    FOREIGN KEY ("couponId") REFERENCES "Coupon"("id") ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "CouponMetalVariant_metalVariantId_fkey"
    FOREIGN KEY ("metalVariantId") REFERENCES "MetalVariant"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "CouponMetalVariant_couponId_metalVariantId_key"
  ON "CouponMetalVariant"("couponId", "metalVariantId");
CREATE INDEX "CouponMetalVariant_couponId_idx"
  ON "CouponMetalVariant"("couponId");
CREATE INDEX "CouponMetalVariant_metalVariantId_idx"
  ON "CouponMetalVariant"("metalVariantId");
CREATE INDEX "CouponMetalVariant_jewelryId_idx"
  ON "CouponMetalVariant"("jewelryId");

-- 5) QuantityDiscount: array de IDs de variantes de metal.
ALTER TABLE "QuantityDiscount"
  ADD COLUMN "metalVariantIds" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[];
