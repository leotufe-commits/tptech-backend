-- Migration: Replace per-variant groupId with a unified ArticleGroupItem junction table.
-- Supports ARTICLE (simple, no variants) and VARIANT item types.

-- 1. Create enum
CREATE TYPE "GroupItemType" AS ENUM ('ARTICLE', 'VARIANT');

-- 2. Create junction table
CREATE TABLE "ArticleGroupItem" (
  "id"                 TEXT NOT NULL,
  "groupId"            TEXT NOT NULL,
  "jewelryId"          TEXT NOT NULL,
  "itemType"           "GroupItemType" NOT NULL,
  "articleId"          TEXT,
  "variantId"          TEXT,
  "groupOrder"         INTEGER NOT NULL DEFAULT 0,
  "groupSelectorValue" TEXT NOT NULL DEFAULT '',
  "createdAt"          TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "ArticleGroupItem_pkey" PRIMARY KEY ("id")
);

-- 3. Indexes
CREATE INDEX "ArticleGroupItem_groupId_idx"   ON "ArticleGroupItem"("groupId");
CREATE INDEX "ArticleGroupItem_jewelryId_idx" ON "ArticleGroupItem"("jewelryId");
CREATE INDEX "ArticleGroupItem_articleId_idx" ON "ArticleGroupItem"("articleId");
CREATE INDEX "ArticleGroupItem_variantId_idx" ON "ArticleGroupItem"("variantId");

-- 4. Foreign keys
ALTER TABLE "ArticleGroupItem"
  ADD CONSTRAINT "ArticleGroupItem_groupId_fkey"
  FOREIGN KEY ("groupId") REFERENCES "ArticleGroup"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "ArticleGroupItem"
  ADD CONSTRAINT "ArticleGroupItem_articleId_fkey"
  FOREIGN KEY ("articleId") REFERENCES "Article"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "ArticleGroupItem"
  ADD CONSTRAINT "ArticleGroupItem_variantId_fkey"
  FOREIGN KEY ("variantId") REFERENCES "ArticleVariant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- 5. Migrate existing variant-group memberships
INSERT INTO "ArticleGroupItem"
  ("id", "groupId", "jewelryId", "itemType", "variantId", "groupOrder", "groupSelectorValue", "createdAt")
SELECT
  gen_random_uuid()::text,
  v."groupId",
  v."jewelryId",
  'VARIANT'::"GroupItemType",
  v."id",
  v."groupOrder",
  v."groupSelectorValue",
  NOW()
FROM "ArticleVariant" v
WHERE v."groupId" IS NOT NULL
  AND v."deletedAt" IS NULL;

-- 6. Remove group fields from ArticleVariant
ALTER TABLE "ArticleVariant" DROP CONSTRAINT IF EXISTS "ArticleVariant_groupId_fkey";
DROP INDEX IF EXISTS "ArticleVariant_groupId_idx";
ALTER TABLE "ArticleVariant" DROP COLUMN IF EXISTS "groupId";
ALTER TABLE "ArticleVariant" DROP COLUMN IF EXISTS "groupOrder";
ALTER TABLE "ArticleVariant" DROP COLUMN IF EXISTS "groupSelectorValue";
