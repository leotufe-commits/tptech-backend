-- ============================================================
-- Migration: attribute_defs_architecture
-- Introduce global ArticleAttributeDef + ArticleAttributeDefOption
-- Repurpose ArticleCategoryAttribute as assignment table
-- ============================================================

-- 1. Create ArticleAttributeDef (global tenant-level attribute definition)
CREATE TABLE "ArticleAttributeDef" (
    "id"           TEXT NOT NULL,
    "jewelryId"    TEXT NOT NULL,
    "name"         TEXT NOT NULL,
    "code"         TEXT NOT NULL DEFAULT '',
    "inputType"    "CategoryAttributeInputType" NOT NULL,
    "helpText"     TEXT NOT NULL DEFAULT '',
    "unit"         TEXT NOT NULL DEFAULT '',
    "defaultValue" TEXT NOT NULL DEFAULT '',
    "isActive"     BOOLEAN NOT NULL DEFAULT true,
    "deletedAt"    TIMESTAMP(3),
    "createdAt"    TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt"    TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "ArticleAttributeDef_pkey" PRIMARY KEY ("id")
);

-- 2. Create ArticleAttributeDefOption (options for global defs)
CREATE TABLE "ArticleAttributeDefOption" (
    "id"           TEXT NOT NULL,
    "definitionId" TEXT NOT NULL,
    "label"        TEXT NOT NULL,
    "value"        TEXT NOT NULL,
    "colorHex"     TEXT NOT NULL DEFAULT '',
    "sortOrder"    INTEGER NOT NULL DEFAULT 0,
    "isActive"     BOOLEAN NOT NULL DEFAULT true,
    "createdAt"    TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt"    TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "ArticleAttributeDefOption_pkey" PRIMARY KEY ("id")
);

-- 3. Migrate existing ArticleCategoryAttribute data → ArticleAttributeDef
--    Reuse the same IDs for zero-friction migration
INSERT INTO "ArticleAttributeDef"
    ("id", "jewelryId", "name", "code", "inputType", "helpText", "unit", "defaultValue",
     "isActive", "deletedAt", "createdAt", "updatedAt")
SELECT
    "id", "jewelryId", "name", "code", "inputType", "helpText", "unit", "defaultValue",
    "isActive", "deletedAt", "createdAt", "updatedAt"
FROM "ArticleCategoryAttribute";

-- 4. Migrate old options → ArticleAttributeDefOption
--    definitionId = attributeId (since we reused the same IDs above)
INSERT INTO "ArticleAttributeDefOption"
    ("id", "definitionId", "label", "value", "colorHex", "sortOrder", "isActive", "createdAt", "updatedAt")
SELECT
    "id", "attributeId", "label", "value", "colorHex", "sortOrder", "isActive", "createdAt", "updatedAt"
FROM "ArticleCategoryAttributeOption";

-- 5. Add definitionId to ArticleCategoryAttribute (nullable during migration)
ALTER TABLE "ArticleCategoryAttribute" ADD COLUMN "definitionId" TEXT;

-- 6. Set definitionId = id for all existing records (IDs match the defs we just created)
UPDATE "ArticleCategoryAttribute" SET "definitionId" = "id";

-- 7. Make definitionId NOT NULL
ALTER TABLE "ArticleCategoryAttribute" ALTER COLUMN "definitionId" SET NOT NULL;

-- 8. Add foreign key constraints
ALTER TABLE "ArticleAttributeDef"
    ADD CONSTRAINT "ArticleAttributeDef_jewelryId_fkey"
    FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "ArticleAttributeDefOption"
    ADD CONSTRAINT "ArticleAttributeDefOption_definitionId_fkey"
    FOREIGN KEY ("definitionId") REFERENCES "ArticleAttributeDef"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "ArticleCategoryAttribute"
    ADD CONSTRAINT "ArticleCategoryAttribute_definitionId_fkey"
    FOREIGN KEY ("definitionId") REFERENCES "ArticleAttributeDef"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- 9. Create indexes for new tables
CREATE INDEX "ArticleAttributeDef_jewelryId_idx" ON "ArticleAttributeDef"("jewelryId");
CREATE INDEX "ArticleAttributeDef_jewelryId_isActive_idx" ON "ArticleAttributeDef"("jewelryId", "isActive");
CREATE INDEX "ArticleAttributeDef_deletedAt_idx" ON "ArticleAttributeDef"("deletedAt");
CREATE INDEX "ArticleAttributeDef_jewelryId_deletedAt_idx" ON "ArticleAttributeDef"("jewelryId", "deletedAt");
CREATE INDEX "ArticleAttributeDefOption_definitionId_idx" ON "ArticleAttributeDefOption"("definitionId");
CREATE INDEX "ArticleAttributeDefOption_definitionId_isActive_idx" ON "ArticleAttributeDefOption"("definitionId", "isActive");
CREATE INDEX "ArticleCategoryAttribute_definitionId_idx" ON "ArticleCategoryAttribute"("definitionId");

-- 10. Drop old definition columns from ArticleCategoryAttribute (moved to ArticleAttributeDef)
ALTER TABLE "ArticleCategoryAttribute" DROP COLUMN "name";
ALTER TABLE "ArticleCategoryAttribute" DROP COLUMN "code";
ALTER TABLE "ArticleCategoryAttribute" DROP COLUMN "inputType";
ALTER TABLE "ArticleCategoryAttribute" DROP COLUMN "helpText";
ALTER TABLE "ArticleCategoryAttribute" DROP COLUMN "unit";
ALTER TABLE "ArticleCategoryAttribute" DROP COLUMN "defaultValue";

-- 11. Drop old options table (all data migrated to ArticleAttributeDefOption)
DROP TABLE "ArticleCategoryAttributeOption";
