-- CreateEnum
DO $$ BEGIN
  CREATE TYPE "UserPreferenceScope" AS ENUM ('SALES_INVOICE');
EXCEPTION WHEN duplicate_object THEN null; END $$;

-- CreateTable
CREATE TABLE IF NOT EXISTS "UserPreference" (
  "id"                 TEXT NOT NULL,
  "jewelryId"          TEXT NOT NULL,
  "userId"             TEXT NOT NULL,
  "scope"              "UserPreferenceScope" NOT NULL,
  "defaultWarehouseId" TEXT,
  "defaultSellerId"    TEXT,
  "defaultPriceListId" TEXT,
  "defaultChannelId"   TEXT,
  "defaultCurrencyId"  TEXT,
  "createdAt"          TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt"          TIMESTAMP(3) NOT NULL,
  CONSTRAINT "UserPreference_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX IF NOT EXISTS "UserPreference_userId_scope_key"
  ON "UserPreference"("userId", "scope");
CREATE INDEX IF NOT EXISTS "UserPreference_jewelryId_idx"
  ON "UserPreference"("jewelryId");
CREATE INDEX IF NOT EXISTS "UserPreference_userId_idx"
  ON "UserPreference"("userId");

-- Backfill: migrar el almacén favorito actual (User.favoriteWarehouseId)
-- hacia UserPreference scope SALES_INVOICE. User.favoriteWarehouseId queda
-- legacy/sin uso (no se borra todavía).
INSERT INTO "UserPreference" (
  "id", "jewelryId", "userId", "scope", "defaultWarehouseId", "createdAt", "updatedAt"
)
SELECT
  gen_random_uuid()::text,
  u."jewelryId",
  u."id",
  'SALES_INVOICE'::"UserPreferenceScope",
  u."favoriteWarehouseId",
  NOW(),
  NOW()
FROM "User" u
WHERE u."favoriteWarehouseId" IS NOT NULL
  AND u."deletedAt" IS NULL
ON CONFLICT ("userId", "scope") DO NOTHING;
