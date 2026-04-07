-- AddLineAdjustmentToCostLine
-- Agrega campos de bonificación/recargo por línea a ArticleCostLine.
-- Default vacío → sin efecto en líneas existentes.

ALTER TABLE "ArticleCostLine" ADD COLUMN "lineAdjKind"  TEXT         NOT NULL DEFAULT '';
ALTER TABLE "ArticleCostLine" ADD COLUMN "lineAdjType"  TEXT         NOT NULL DEFAULT '';
ALTER TABLE "ArticleCostLine" ADD COLUMN "lineAdjValue" DECIMAL(14,4);
