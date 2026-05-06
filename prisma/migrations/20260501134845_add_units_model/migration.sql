-- CreateEnum
CREATE TYPE "UnitType" AS ENUM ('QUANTITY', 'WEIGHT', 'LENGTH', 'VOLUME', 'OTHER');

-- CreateTable
CREATE TABLE "Unit" (
    "id" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "code" TEXT NOT NULL,
    "type" "UnitType" NOT NULL,
    "isSystem" BOOLEAN NOT NULL DEFAULT false,
    "isFavorite" BOOLEAN NOT NULL DEFAULT false,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "sortOrder" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),

    CONSTRAINT "Unit_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "Unit_jewelryId_type_isActive_idx" ON "Unit"("jewelryId", "type", "isActive");

-- CreateIndex
CREATE INDEX "Unit_jewelryId_type_isFavorite_idx" ON "Unit"("jewelryId", "type", "isFavorite");

-- CreateIndex
CREATE INDEX "Unit_deletedAt_idx" ON "Unit"("deletedAt");

-- CreateIndex
CREATE UNIQUE INDEX "Unit_jewelryId_type_code_key" ON "Unit"("jewelryId", "type", "code");

-- CreateIndex
CREATE UNIQUE INDEX "Unit_jewelryId_type_name_key" ON "Unit"("jewelryId", "type", "name");

-- AddForeignKey
ALTER TABLE "Unit" ADD CONSTRAINT "Unit_jewelryId_fkey" FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- ─────────────────────────────────────────────────────────────────────────────
-- Data migration: copiar CatalogItem (UNIT_OF_MEASURE / WEIGHT_UNIT / MULTIPLIER_BASE) → Unit
--   - UNIT_OF_MEASURE  → LENGTH
--   - WEIGHT_UNIT      → WEIGHT
--   - MULTIPLIER_BASE  → WEIGHT
-- code: si el label contiene "( ... )" se extrae el contenido; sino se usa el label.
-- DISTINCT ON deduplica por (jewelryId, type, code) priorizando isFavorite y createdAt más antiguo.
-- ON CONFLICT DO NOTHING evita pisar registros con el mismo (jewelryId, type, code|name).
-- ─────────────────────────────────────────────────────────────────────────────
INSERT INTO "Unit" ("id", "jewelryId", "name", "code", "type", "isSystem", "isFavorite", "isActive", "sortOrder", "createdAt", "updatedAt", "deletedAt")
SELECT DISTINCT ON (sub."jewelryId", sub."typeMapped", sub."codeExtracted")
    'umig_' || replace(gen_random_uuid()::text, '-', '') AS "id",
    sub."jewelryId",
    sub."label"         AS "name",
    sub."codeExtracted" AS "code",
    sub."typeMapped"    AS "type",
    sub."isSystem",
    sub."isFavorite",
    sub."isActive",
    sub."sortOrder",
    sub."createdAt",
    sub."updatedAt",
    sub."deletedAt"
FROM (
    SELECT
        ci."jewelryId",
        ci."label",
        ci."isSystem",
        ci."isFavorite",
        ci."isActive",
        ci."sortOrder",
        ci."createdAt",
        ci."updatedAt",
        ci."deletedAt",
        CASE ci."type"
            WHEN 'UNIT_OF_MEASURE' THEN 'LENGTH'::"UnitType"
            WHEN 'WEIGHT_UNIT'     THEN 'WEIGHT'::"UnitType"
            WHEN 'MULTIPLIER_BASE' THEN 'WEIGHT'::"UnitType"
        END AS "typeMapped",
        COALESCE(
            NULLIF(TRIM((regexp_match(ci."label", '\(([^)]+)\)'))[1]), ''),
            ci."label"
        ) AS "codeExtracted"
    FROM "CatalogItem" ci
    WHERE ci."type" IN ('UNIT_OF_MEASURE', 'WEIGHT_UNIT', 'MULTIPLIER_BASE')
      AND ci."deletedAt" IS NULL
) sub
ORDER BY sub."jewelryId", sub."typeMapped", sub."codeExtracted", sub."isFavorite" DESC, sub."createdAt" ASC
ON CONFLICT DO NOTHING;

-- ─────────────────────────────────────────────────────────────────────────────
-- Seeds base por tenant (idempotente — ON CONFLICT DO NOTHING)
-- OTHER queda intencionalmente sin valores por defecto.
-- ─────────────────────────────────────────────────────────────────────────────
INSERT INTO "Unit" ("id", "jewelryId", "name", "code", "type", "isSystem", "isFavorite", "isActive", "sortOrder", "createdAt", "updatedAt")
SELECT
    'useed_' || replace(gen_random_uuid()::text, '-', ''),
    j."id",
    seed."name",
    seed."code",
    seed."type"::"UnitType",
    true,
    seed."isFavorite",
    true,
    seed."sortOrder",
    NOW(),
    NOW()
FROM "Jewelry" j
CROSS JOIN (VALUES
    ('Unidad',     'UND',  'QUANTITY', true,  0),
    ('Par',        'PAR',  'QUANTITY', false, 1),
    ('Pack',       'PACK', 'QUANTITY', false, 2),
    ('Gramo',      'g',    'WEIGHT',   true,  0),
    ('Kilogramo',  'kg',   'WEIGHT',   false, 1),
    ('Kilate',     'kt',   'WEIGHT',   false, 2),
    ('Milímetro',  'mm',   'LENGTH',   false, 0),
    ('Centímetro', 'cm',   'LENGTH',   true,  1),
    ('Metro',      'm',    'LENGTH',   false, 2),
    ('Mililitro',  'ml',   'VOLUME',   false, 0),
    ('Litro',      'l',    'VOLUME',   false, 1)
) AS seed("name", "code", "type", "isFavorite", "sortOrder")
WHERE j."deletedAt" IS NULL
ON CONFLICT DO NOTHING;
