-- Cambio 1: Agregar MULTIPLIER_BASE al enum CatalogType
ALTER TYPE "CatalogType" ADD VALUE IF NOT EXISTS 'MULTIPLIER_BASE';

-- Cambio 2: Convertir Article.multiplierBase de enum a TEXT
-- Primero migrar datos existentes preservando legibilidad
ALTER TABLE "Article"
  ALTER COLUMN "multiplierBase" TYPE TEXT
  USING CASE "multiplierBase"::text
    WHEN 'GRAMS'   THEN 'Gramos'
    WHEN 'KILATES' THEN 'Kilates'
    WHEN 'UNITS'   THEN 'Unidades'
    ELSE ''
  END;

-- Establecer valor por defecto y NOT NULL
ALTER TABLE "Article" ALTER COLUMN "multiplierBase" SET DEFAULT '';
UPDATE "Article" SET "multiplierBase" = '' WHERE "multiplierBase" IS NULL;
ALTER TABLE "Article" ALTER COLUMN "multiplierBase" SET NOT NULL;
