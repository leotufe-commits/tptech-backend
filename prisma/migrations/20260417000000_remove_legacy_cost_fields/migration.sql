-- ============================================================
-- FASE 3: Eliminar campos legacy del modelo de costos
-- Todos los artículos ya fueron migrados a ArticleCostLine.
-- ============================================================

-- Paso previo: eliminar filas huérfanas de ArticleCostLine
-- que tenían variantId (composición propia de variante).
-- Estas líneas ya no tienen destino en el nuevo schema.
DELETE FROM "ArticleCostLine" WHERE "variantId" IS NOT NULL;

-- ── Article: eliminar columnas legacy ────────────────────────
ALTER TABLE "Article" DROP COLUMN IF EXISTS "costPrice";
ALTER TABLE "Article" DROP COLUMN IF EXISTS "hechuraPrice";
ALTER TABLE "Article" DROP COLUMN IF EXISTS "hechuraPriceMode";
ALTER TABLE "Article" DROP COLUMN IF EXISTS "costCalculationMode";
ALTER TABLE "Article" DROP COLUMN IF EXISTS "multiplierBase";
ALTER TABLE "Article" DROP COLUMN IF EXISTS "multiplierValue";
ALTER TABLE "Article" DROP COLUMN IF EXISTS "multiplierQuantity";
ALTER TABLE "Article" DROP COLUMN IF EXISTS "multiplierCurrencyId";
ALTER TABLE "Article" DROP COLUMN IF EXISTS "manualBaseCost";
ALTER TABLE "Article" DROP COLUMN IF EXISTS "manualCurrencyId";

-- ── ArticleVariant: eliminar columnas legacy ─────────────────
ALTER TABLE "ArticleVariant" DROP COLUMN IF EXISTS "hechuraPriceOverride";
ALTER TABLE "ArticleVariant" DROP COLUMN IF EXISTS "costPrice";

-- ── ArticleCostLine: eliminar columna variantId ───────────────
DROP INDEX IF EXISTS "ArticleCostLine_variantId_idx";
ALTER TABLE "ArticleCostLine" DROP COLUMN IF EXISTS "variantId";

-- ── Eliminar tabla ArticleMetalComposition ────────────────────
DROP TABLE IF EXISTS "ArticleMetalComposition";

-- ── Eliminar enums legacy ─────────────────────────────────────
DROP TYPE IF EXISTS "HechuraPriceMode";
DROP TYPE IF EXISTS "CostCalculationMode";
DROP TYPE IF EXISTS "MultiplierBase";
