-- Etapa 1B (refinamiento UX) — Separar config metal y hechura del documento
--
-- Contexto:
--   La migración previa (20260527140000_document_rounding_scope_etapa_1b)
--   agregó UN par de columnas compartido para metal+hechura
--   (`documentRoundingModeHechura` / `documentRoundingDirectionHechura`).
--   La pantalla de configuración pide que metal y hechura sean configurables
--   por separado (mismo patrón que `PriceList`).
--
-- Cambio:
--   Agregamos las 2 columnas faltantes para METAL. Las columnas existentes
--   de hechura se mantienen sin cambios. Default NONE/NEAREST → tenants
--   existentes mantienen comportamiento (BREAKDOWN sin componente metal
--   efectivo equivale a UNIFIED puro si no hay otros componentes).
--
-- Backward compatibility:
--   · Filas existentes: metal queda en NONE → no afecta a quienes ya tenían
--     configurado solo hechura; tampoco a quienes nunca configuraron nada.
--   · Loader del backend: pasa a leer 4 columnas independientes en lugar de
--     reusar 2 (cambio interno, no rompe API).

ALTER TABLE "Jewelry"
  ADD COLUMN "documentRoundingModeMetal"      "RoundingMode"      NOT NULL DEFAULT 'NONE',
  ADD COLUMN "documentRoundingDirectionMetal" "RoundingDirection" NOT NULL DEFAULT 'NEAREST';
