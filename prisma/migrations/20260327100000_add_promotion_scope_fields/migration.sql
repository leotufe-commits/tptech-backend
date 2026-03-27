-- =========================================================================
-- Rediseño del alcance de Promociones: de campos simples a tablas M2M
-- =========================================================================
-- El modelo original tenía articleId y variantId como FK simples.
-- Esta migración:
--   1. Agrega el enum PromotionScope y la columna scope en Promotion
--   2. Migra los datos existentes (articleId/variantId → registros en tablas junction)
--   3. Elimina articleId y variantId de Promotion
--   4. Crea las 4 tablas de unión: PromotionArticle, PromotionVariant, PromotionCategory, PromotionBrand
-- =========================================================================

-- 1. Crear enum de alcance
CREATE TYPE "PromotionScope" AS ENUM ('ALL', 'ARTICLE', 'VARIANT', 'CATEGORY', 'BRAND');

-- 2. Agregar columna scope (nullable al principio para poder migrar datos)
ALTER TABLE "Promotion" ADD COLUMN "scope" "PromotionScope";

-- 3. Migrar datos existentes al nuevo campo scope
UPDATE "Promotion" SET "scope" = 'VARIANT' WHERE "variantId" IS NOT NULL;
UPDATE "Promotion" SET "scope" = 'ARTICLE' WHERE "articleId" IS NOT NULL AND "variantId" IS NULL;
UPDATE "Promotion" SET "scope" = 'ALL'     WHERE "scope" IS NULL;

-- 4. Hacer scope NOT NULL con default
ALTER TABLE "Promotion" ALTER COLUMN "scope" SET NOT NULL;
ALTER TABLE "Promotion" ALTER COLUMN "scope" SET DEFAULT 'ALL';
CREATE INDEX "Promotion_scope_idx" ON "Promotion"("scope");

-- 5. Crear tablas de unión
CREATE TABLE "PromotionArticle" (
  "id"          TEXT NOT NULL,
  "promotionId" TEXT NOT NULL,
  "articleId"   TEXT NOT NULL,
  "jewelryId"   TEXT NOT NULL,
  CONSTRAINT "PromotionArticle_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "PromotionVariant" (
  "id"          TEXT NOT NULL,
  "promotionId" TEXT NOT NULL,
  "variantId"   TEXT NOT NULL,
  "jewelryId"   TEXT NOT NULL,
  CONSTRAINT "PromotionVariant_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "PromotionCategory" (
  "id"          TEXT NOT NULL,
  "promotionId" TEXT NOT NULL,
  "categoryId"  TEXT NOT NULL,
  "jewelryId"   TEXT NOT NULL,
  CONSTRAINT "PromotionCategory_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "PromotionBrand" (
  "id"          TEXT NOT NULL,
  "promotionId" TEXT NOT NULL,
  "brand"       TEXT NOT NULL,
  "jewelryId"   TEXT NOT NULL,
  CONSTRAINT "PromotionBrand_pkey" PRIMARY KEY ("id")
);

-- 6. Migrar registros existentes (articleId → PromotionArticle, variantId → PromotionVariant)
INSERT INTO "PromotionArticle" ("id", "promotionId", "articleId", "jewelryId")
SELECT gen_random_uuid()::text, p."id", p."articleId", p."jewelryId"
FROM "Promotion" p
WHERE p."articleId" IS NOT NULL AND p."scope" = 'ARTICLE';

INSERT INTO "PromotionVariant" ("id", "promotionId", "variantId", "jewelryId")
SELECT gen_random_uuid()::text, p."id", p."variantId", p."jewelryId"
FROM "Promotion" p
WHERE p."variantId" IS NOT NULL AND p."scope" = 'VARIANT';

-- 7. Eliminar FK constraints y columnas antiguas
ALTER TABLE "Promotion" DROP CONSTRAINT IF EXISTS "Promotion_articleId_fkey";
ALTER TABLE "Promotion" DROP CONSTRAINT IF EXISTS "Promotion_variantId_fkey";
DROP INDEX IF EXISTS "Promotion_articleId_idx";
DROP INDEX IF EXISTS "Promotion_variantId_idx";
ALTER TABLE "Promotion" DROP COLUMN IF EXISTS "articleId";
ALTER TABLE "Promotion" DROP COLUMN IF EXISTS "variantId";

-- 8. FK constraints para las tablas de unión
ALTER TABLE "PromotionArticle"
  ADD CONSTRAINT "PromotionArticle_promotionId_fkey"
  FOREIGN KEY ("promotionId") REFERENCES "Promotion"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "PromotionArticle"
  ADD CONSTRAINT "PromotionArticle_articleId_fkey"
  FOREIGN KEY ("articleId") REFERENCES "Article"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "PromotionVariant"
  ADD CONSTRAINT "PromotionVariant_promotionId_fkey"
  FOREIGN KEY ("promotionId") REFERENCES "Promotion"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "PromotionVariant"
  ADD CONSTRAINT "PromotionVariant_variantId_fkey"
  FOREIGN KEY ("variantId") REFERENCES "ArticleVariant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "PromotionCategory"
  ADD CONSTRAINT "PromotionCategory_promotionId_fkey"
  FOREIGN KEY ("promotionId") REFERENCES "Promotion"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "PromotionCategory"
  ADD CONSTRAINT "PromotionCategory_categoryId_fkey"
  FOREIGN KEY ("categoryId") REFERENCES "ArticleCategory"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "PromotionBrand"
  ADD CONSTRAINT "PromotionBrand_promotionId_fkey"
  FOREIGN KEY ("promotionId") REFERENCES "Promotion"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- 9. Unique constraints
CREATE UNIQUE INDEX "PromotionArticle_promotionId_articleId_key"  ON "PromotionArticle"("promotionId", "articleId");
CREATE UNIQUE INDEX "PromotionVariant_promotionId_variantId_key"   ON "PromotionVariant"("promotionId", "variantId");
CREATE UNIQUE INDEX "PromotionCategory_promotionId_categoryId_key" ON "PromotionCategory"("promotionId", "categoryId");
CREATE UNIQUE INDEX "PromotionBrand_promotionId_brand_key"         ON "PromotionBrand"("promotionId", "brand");

-- 10. Índices
CREATE INDEX "PromotionArticle_promotionId_idx"  ON "PromotionArticle"("promotionId");
CREATE INDEX "PromotionArticle_articleId_idx"    ON "PromotionArticle"("articleId");
CREATE INDEX "PromotionArticle_jewelryId_idx"    ON "PromotionArticle"("jewelryId");

CREATE INDEX "PromotionVariant_promotionId_idx"  ON "PromotionVariant"("promotionId");
CREATE INDEX "PromotionVariant_variantId_idx"    ON "PromotionVariant"("variantId");
CREATE INDEX "PromotionVariant_jewelryId_idx"    ON "PromotionVariant"("jewelryId");

CREATE INDEX "PromotionCategory_promotionId_idx" ON "PromotionCategory"("promotionId");
CREATE INDEX "PromotionCategory_categoryId_idx"  ON "PromotionCategory"("categoryId");
CREATE INDEX "PromotionCategory_jewelryId_idx"   ON "PromotionCategory"("jewelryId");

CREATE INDEX "PromotionBrand_promotionId_idx"    ON "PromotionBrand"("promotionId");
CREATE INDEX "PromotionBrand_jewelryId_idx"      ON "PromotionBrand"("jewelryId");
