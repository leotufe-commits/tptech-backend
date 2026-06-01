-- Etapa Cierre-Rounding (POLICY §R-Rounding-6) — Sale.engineTotal
--
-- Snapshot del `documentTotals.total` emitido por el motor INMEDIATAMENTE
-- después del rounding (capa 15 del pipeline) y ANTES de cualquier ajuste
-- manual humano futuro (capa 17, Etapa siguiente). Precondición arquitectónica
-- para que cuando se implemente `manualAdjustment`, exista una referencia
-- explícita en DB del "total calculado por el motor" sin tener que parsear
-- snapshots JSON.
--
-- Backward compatibility:
--   · Aditiva, NOT NULL no aplicable (filas existentes no tienen el valor).
--   · Hoy `Sale.total === Sale.engineTotal` porque manualAdjustment todavía
--     no existe. Cuando se implemente:
--         Sale.total = engineTotal + manualAdjustment.totals.monetaryAdjustment
--   · Filas históricas (pre-migración) quedan con engineTotal=NULL — los
--     consumers deben caer a `Sale.total` cuando engineTotal es null.

ALTER TABLE "Sale"
  ADD COLUMN "engineTotal" DECIMAL(14, 2);
