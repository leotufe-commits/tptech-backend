-- Etapa Manual-Adjustment 1 — Sale.manualAdjustmentInput + Sale.manualAdjustmentSnapshot
--
-- Override humano final post-rounding (POLICY §R-Rounding-1 capa 17).
-- Solo scope=UNIFIED global del documento en esta etapa.
--
-- `manualAdjustmentInput`    — DRAFT: intención del usuario, persiste hasta confirm.
-- `manualAdjustmentSnapshot` — CONFIRMED: snapshot inmutable con audit (who/when/delta).
--
-- Backward compatibility:
--   · Aditiva, nullable.
--   · Ventas históricas quedan con NULL en ambas columnas (sin ajuste).
--   · Sin manualAdjustment, `Sale.total === Sale.engineTotal`.
--   · Con manualAdjustment, `Sale.total = engineTotal + snapshot.totals.monetaryAdjustment`.
--
-- PDFs y cuenta corriente leen `Sale.total` directamente — coherentes por
-- construcción.

ALTER TABLE "Sale"
  ADD COLUMN "manualAdjustmentInput"    JSONB,
  ADD COLUMN "manualAdjustmentSnapshot" JSONB;
