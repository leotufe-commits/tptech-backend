-- Etapa 1B — Sistema de redondeo unificado por comprobante
-- Migración aditiva, default UNIFIED, backward compatible.
--
-- Cambios:
--   1. Nuevo enum `DocumentRoundingScope` (UNIFIED | BREAKDOWN | BOTH).
--   2. Jewelry: nuevas columnas para scope + config BREAKDOWN (metal + hechura).
--      Las columnas UNIFIED existentes (documentRoundingMode/Direction) se
--      siguen usando cuando scope = UNIFIED o BOTH.
--   3. Sale: nueva columna `documentRoundingSnapshot Json?` que congela el
--      resultado del redondeo aplicado al confirmar.
--
-- Ninguna columna nueva es NOT NULL sin default → todas las filas existentes
-- quedan en UNIFIED + NONE/NEAREST + snapshot null, equivalente al
-- comportamiento previo a Etapa 1B.

-- 1. Enum DocumentRoundingScope
CREATE TYPE "DocumentRoundingScope" AS ENUM ('UNIFIED', 'BREAKDOWN', 'BOTH');

-- 2. Jewelry: scope + config breakdown
ALTER TABLE "Jewelry"
  ADD COLUMN "documentRoundingScope"            "DocumentRoundingScope" NOT NULL DEFAULT 'UNIFIED',
  ADD COLUMN "documentRoundingModeHechura"      "RoundingMode"          NOT NULL DEFAULT 'NONE',
  ADD COLUMN "documentRoundingDirectionHechura" "RoundingDirection"     NOT NULL DEFAULT 'NEAREST';

-- 3. Sale: snapshot inmutable del redondeo aplicado al confirmar
ALTER TABLE "Sale"
  ADD COLUMN "documentRoundingSnapshot" JSONB;
