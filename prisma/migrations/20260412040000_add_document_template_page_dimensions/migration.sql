-- Renombrar pageSize → pageSizePreset
ALTER TABLE "DocumentTemplate" RENAME COLUMN "pageSize" TO "pageSizePreset";

-- Agregar campos de dimensiones y flag de personalizado
ALTER TABLE "DocumentTemplate" ADD COLUMN "isCustomSize" BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE "DocumentTemplate" ADD COLUMN "pageWidthMm"  DECIMAL(8,2) NOT NULL DEFAULT 210;
ALTER TABLE "DocumentTemplate" ADD COLUMN "pageHeightMm" DECIMAL(8,2) NOT NULL DEFAULT 297;
