-- Fix WEIGHT_UNIT catalog: rename "Unidad" → "Unidades" and ensure it's the favorite.
-- Affects tenants that were initialized before this change.

-- 1. Rename "Unidad" (singular) to "Unidades" (plural)
UPDATE "CatalogItem"
SET label = 'Unidades'
WHERE type = 'WEIGHT_UNIT'
  AND label = 'Unidad';

-- 2. Quitar favorito de cualquier otro ítem WEIGHT_UNIT que lo tenga
UPDATE "CatalogItem"
SET "isFavorite" = false
WHERE type = 'WEIGHT_UNIT'
  AND label <> 'Unidades'
  AND "isFavorite" = true;

-- 3. Marcar "Unidades" como favorito en todos los tenants que lo tengan
UPDATE "CatalogItem"
SET "isFavorite" = true
WHERE type = 'WEIGHT_UNIT'
  AND label = 'Unidades'
  AND "isFavorite" = false;
