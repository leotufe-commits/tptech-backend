-- Etapa C-comercial / C1 (POLICY §R-Rounding-14) — Schema aditivo para
-- redondeo COMERCIAL PHYSICAL por metal padre en `PriceList`.
--
-- Contrato canónico del modo DESGLOSADO (POLICY §R-Rounding-14):
--   DESGLOSADO = metal padre físico + hechura/saldo monetario.
--
-- Este schema agrega los dos campos que permitirán a la PriceList declarar
-- su redondeo de metal en gramos físicos por metal padre, paralelo al
-- redondeo financiero PHYSICAL (Etapa D, capa 16 — Jewelry):
--
--   · `commercialRoundingMetalDomain` — discriminador MONETARY (legacy) |
--     PHYSICAL (canónico). Reusa el enum `DocumentRoundingMetalDomain`
--     creado en `20260528150000_jewelry_document_physical_rounding`.
--   · `commercialPhysicalRoundingConfig` — JSON nullable con el mismo
--     shape que `documentPhysicalRoundingConfig`:
--        { byMetalParentId: { [metalId]: { mode, direction } },
--          fallback: { mode, direction } }
--
-- C1 NO toca runtime — los campos quedan disponibles para que la Etapa C2
-- (helper) y C3 (motor de lista) los lean. Hoy nadie los consume.
--
-- Migración ADITIVA — `commercialRoundingMetalDomain` con DEFAULT MONETARY
-- garantiza back-compat total: todas las listas existentes mantienen el
-- comportamiento actual (redondeo legacy del subtotal $ del metal por
-- línea). Solo las listas que el operador edite explícitamente a PHYSICAL
-- entrarán al nuevo path cuando se implemente.

-- ─────────────────────────────────────────────────────────────────────────
-- Columnas nuevas en PriceList
-- ─────────────────────────────────────────────────────────────────────────

ALTER TABLE "PriceList"
  ADD COLUMN "commercialRoundingMetalDomain" "DocumentRoundingMetalDomain"
    NOT NULL DEFAULT 'MONETARY',
  ADD COLUMN "commercialPhysicalRoundingConfig" JSONB;
