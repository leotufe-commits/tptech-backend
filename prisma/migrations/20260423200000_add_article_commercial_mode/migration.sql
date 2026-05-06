-- ============================================================================
-- Combo Comercial — modalidad nueva de Article
-- ----------------------------------------------------------------------------
-- Agrega:
--   · enum ArticleCommercialMode (NORMAL, COMBO_COMMERCIAL)
--   · enum ComboAdjustmentKind   (NONE, DISCOUNT_PERCENT, DISCOUNT_FIXED, SURCHARGE_PERCENT)
--   · columnas commercialMode, comboAdjustmentKind, comboAdjustmentValue en Article
--   · índice (jewelryId, commercialMode)
--
-- Defaults seguros (NORMAL / NONE / NULL): no rompe artículos existentes.
-- ============================================================================

-- Enums nuevos
CREATE TYPE "ArticleCommercialMode" AS ENUM ('NORMAL', 'COMBO_COMMERCIAL');
CREATE TYPE "ComboAdjustmentKind"   AS ENUM ('NONE', 'DISCOUNT_PERCENT', 'DISCOUNT_FIXED', 'SURCHARGE_PERCENT');

-- Columnas nuevas en Article
ALTER TABLE "Article"
  ADD COLUMN "commercialMode"       "ArticleCommercialMode" NOT NULL DEFAULT 'NORMAL',
  ADD COLUMN "comboAdjustmentKind"  "ComboAdjustmentKind"   NOT NULL DEFAULT 'NONE',
  ADD COLUMN "comboAdjustmentValue" DECIMAL(14, 4);

-- Índice para queries del listado por modo comercial
CREATE INDEX "Article_jewelryId_commercialMode_idx" ON "Article"("jewelryId", "commercialMode");
