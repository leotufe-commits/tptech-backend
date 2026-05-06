-- ─────────────────────────────────────────────────────────────────────────────
-- Cleanup legacy unit catalog types (Fase 6 — unificación de Unidades)
--
-- Las unidades viven en el modelo Unit (creado en Fase 2). Estos 3 valores del
-- enum CatalogType ya no se usan. Borramos los registros y removemos los
-- valores del enum para evitar nuevos inserts.
-- ─────────────────────────────────────────────────────────────────────────────

-- 1) Borrar todos los CatalogItem de los 3 tipos legacy (TPTech aún no está
--    en producción y los datos se migraron a Unit en la migración previa).
DELETE FROM "CatalogItem"
WHERE "type" IN ('UNIT_OF_MEASURE', 'WEIGHT_UNIT', 'MULTIPLIER_BASE');

-- 2) Recrear el enum CatalogType sin los 3 valores legacy.
--    PostgreSQL no permite DROP VALUE; el patrón estándar es crear un nuevo
--    type, hacer el ALTER COLUMN y dropear el viejo.
BEGIN;
CREATE TYPE "CatalogType_new" AS ENUM (
  'IVA_CONDITION',
  'PHONE_PREFIX',
  'CITY',
  'PROVINCE',
  'COUNTRY',
  'DOCUMENT_TYPE',
  'PAYMENT_TERM',
  'ARTICLE_BRAND',
  'ARTICLE_MANUFACTURER'
);

ALTER TABLE "CatalogItem"
  ALTER COLUMN "type" TYPE "CatalogType_new" USING ("type"::text::"CatalogType_new");

ALTER TYPE "CatalogType" RENAME TO "CatalogType_old";
ALTER TYPE "CatalogType_new" RENAME TO "CatalogType";
DROP TYPE "public"."CatalogType_old";
COMMIT;
