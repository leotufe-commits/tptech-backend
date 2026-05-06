-- FASE 2 — variante específica como componente de costo
-- Nullable: las líneas existentes mantienen su comportamiento (componente
-- referencia al artículo padre). Cuando catalogVariantId está poblado, el
-- backend valida que la variante pertenezca al catalogItemId.
ALTER TABLE "ArticleCostLine" ADD COLUMN "catalogVariantId" TEXT;

ALTER TABLE "ArticleCostLine"
  ADD CONSTRAINT "ArticleCostLine_catalogVariantId_fkey"
  FOREIGN KEY ("catalogVariantId") REFERENCES "ArticleVariant"("id")
  ON DELETE SET NULL ON UPDATE CASCADE;

CREATE INDEX "ArticleCostLine_catalogVariantId_idx"
  ON "ArticleCostLine"("catalogVariantId");
