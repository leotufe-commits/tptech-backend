-- Etapa D2 (POLICY §R-Rounding-13) — Configuración de redondeo automático
-- físico de gramos por metal padre, persistida en Jewelry.
--
-- Discriminador excluyente entre el redondeo metal $ actual (MONETARY) y
-- el redondeo físico de gramos futuro (PHYSICAL). Default MONETARY ⇒
-- back-compat total: todos los tenants existentes siguen igual.
--
-- D2 NO toca runtime — los campos nuevos quedan disponibles para que la
-- Etapa D3 los lea desde `pricing-engine.document.ts` (capa 16). Hoy nadie
-- los consume todavía.
--
-- Migración ADITIVA — campos nullable o con DEFAULT. Sin riesgo para
-- tenants productivos.

-- ─────────────────────────────────────────────────────────────────────────
-- Enums nuevos
-- ─────────────────────────────────────────────────────────────────────────

CREATE TYPE "DocumentRoundingMetalDomain" AS ENUM ('MONETARY', 'PHYSICAL');

CREATE TYPE "PhysicalRoundingMode" AS ENUM (
  'NONE',
  'INTEGER',
  'DECIMAL_1',
  'DECIMAL_2',
  'HALF',
  'QUARTER'
);

CREATE TYPE "PhysicalRoundingDirection" AS ENUM ('NEAREST', 'UP', 'DOWN');

-- ─────────────────────────────────────────────────────────────────────────
-- Columnas nuevas en Jewelry
-- ─────────────────────────────────────────────────────────────────────────

ALTER TABLE "Jewelry"
  ADD COLUMN "documentRoundingMetalDomain" "DocumentRoundingMetalDomain"
    NOT NULL DEFAULT 'MONETARY',
  ADD COLUMN "documentPhysicalRoundingConfig" JSONB;
