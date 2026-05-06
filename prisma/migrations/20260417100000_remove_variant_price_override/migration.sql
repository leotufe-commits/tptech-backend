-- Migration: remove priceOverride from ArticleVariant
--
-- REGLA: Las variantes no tienen precio propio.
-- El precio de venta siempre se resuelve desde el artículo padre.
-- priceOverride violaba esta regla: permitía que una variante divergiera del padre.

-- Primero nulleamos todos los valores existentes (limpieza de datos)
UPDATE "ArticleVariant" SET "priceOverride" = NULL WHERE "priceOverride" IS NOT NULL;

-- Luego eliminamos la columna
ALTER TABLE "ArticleVariant" DROP COLUMN IF EXISTS "priceOverride";
