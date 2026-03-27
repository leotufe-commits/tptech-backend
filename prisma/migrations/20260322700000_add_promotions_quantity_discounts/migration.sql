-- CreateEnum: PromotionType
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'PromotionType') THEN
    CREATE TYPE "PromotionType" AS ENUM ('FIXED', 'PERCENTAGE');
  END IF;
END $$;

-- CreateTable: Promotion
CREATE TABLE IF NOT EXISTS "Promotion" (
    "id"            TEXT NOT NULL,
    "jewelryId"     TEXT NOT NULL,
    "name"          TEXT NOT NULL,
    "type"          "PromotionType" NOT NULL,
    "value"         DECIMAL(14,4) NOT NULL,
    "articleId"     TEXT,
    "variantId"     TEXT,
    "validFrom"     TIMESTAMP(3),
    "validTo"       TIMESTAMP(3),
    "untilStockEnd" BOOLEAN NOT NULL DEFAULT false,
    "priority"      INTEGER NOT NULL DEFAULT 0,
    "isActive"      BOOLEAN NOT NULL DEFAULT true,
    "notes"         TEXT NOT NULL DEFAULT '',
    "deletedAt"     TIMESTAMP(3),
    "createdAt"     TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt"     TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "Promotion_pkey" PRIMARY KEY ("id")
);

-- CreateTable: QuantityDiscount
CREATE TABLE IF NOT EXISTS "QuantityDiscount" (
    "id"          TEXT NOT NULL,
    "jewelryId"   TEXT NOT NULL,
    "articleId"   TEXT,
    "variantId"   TEXT,
    "minQty"      DECIMAL(14,4) NOT NULL,
    "type"        "PromotionType" NOT NULL,
    "value"       DECIMAL(14,4) NOT NULL,
    "isActive"    BOOLEAN NOT NULL DEFAULT true,
    "sortOrder"   INTEGER NOT NULL DEFAULT 0,
    "deletedAt"   TIMESTAMP(3),
    "createdAt"   TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt"   TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "QuantityDiscount_pkey" PRIMARY KEY ("id")
);

-- AddForeignKeys: Promotion
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'Promotion_jewelryId_fkey'
  ) THEN
    ALTER TABLE "Promotion" ADD CONSTRAINT "Promotion_jewelryId_fkey"
      FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'Promotion_articleId_fkey'
  ) THEN
    ALTER TABLE "Promotion" ADD CONSTRAINT "Promotion_articleId_fkey"
      FOREIGN KEY ("articleId") REFERENCES "Article"("id") ON DELETE SET NULL ON UPDATE CASCADE;
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'Promotion_variantId_fkey'
  ) THEN
    ALTER TABLE "Promotion" ADD CONSTRAINT "Promotion_variantId_fkey"
      FOREIGN KEY ("variantId") REFERENCES "ArticleVariant"("id") ON DELETE SET NULL ON UPDATE CASCADE;
  END IF;
END $$;

-- AddForeignKeys: QuantityDiscount
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'QuantityDiscount_jewelryId_fkey'
  ) THEN
    ALTER TABLE "QuantityDiscount" ADD CONSTRAINT "QuantityDiscount_jewelryId_fkey"
      FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'QuantityDiscount_articleId_fkey'
  ) THEN
    ALTER TABLE "QuantityDiscount" ADD CONSTRAINT "QuantityDiscount_articleId_fkey"
      FOREIGN KEY ("articleId") REFERENCES "Article"("id") ON DELETE SET NULL ON UPDATE CASCADE;
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'QuantityDiscount_variantId_fkey'
  ) THEN
    ALTER TABLE "QuantityDiscount" ADD CONSTRAINT "QuantityDiscount_variantId_fkey"
      FOREIGN KEY ("variantId") REFERENCES "ArticleVariant"("id") ON DELETE SET NULL ON UPDATE CASCADE;
  END IF;
END $$;

-- Indexes: Promotion
CREATE INDEX IF NOT EXISTS "Promotion_jewelryId_idx"          ON "Promotion"("jewelryId");
CREATE INDEX IF NOT EXISTS "Promotion_articleId_idx"          ON "Promotion"("articleId");
CREATE INDEX IF NOT EXISTS "Promotion_variantId_idx"          ON "Promotion"("variantId");
CREATE INDEX IF NOT EXISTS "Promotion_jewelryId_isActive_idx" ON "Promotion"("jewelryId", "isActive");
CREATE INDEX IF NOT EXISTS "Promotion_deletedAt_idx"          ON "Promotion"("deletedAt");

-- Indexes: QuantityDiscount
CREATE INDEX IF NOT EXISTS "QuantityDiscount_jewelryId_idx"  ON "QuantityDiscount"("jewelryId");
CREATE INDEX IF NOT EXISTS "QuantityDiscount_articleId_idx"  ON "QuantityDiscount"("articleId");
CREATE INDEX IF NOT EXISTS "QuantityDiscount_variantId_idx"  ON "QuantityDiscount"("variantId");
CREATE INDEX IF NOT EXISTS "QuantityDiscount_deletedAt_idx"  ON "QuantityDiscount"("deletedAt");

-- Add snapshot columns to SaleLine (idempotent)
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'SaleLine' AND column_name = 'priceSource'
  ) THEN
    ALTER TABLE "SaleLine" ADD COLUMN "priceSource"        TEXT NOT NULL DEFAULT '';
    ALTER TABLE "SaleLine" ADD COLUMN "appliedPriceListId" TEXT;
    ALTER TABLE "SaleLine" ADD COLUMN "appliedPromotionId" TEXT;
    ALTER TABLE "SaleLine" ADD COLUMN "appliedDiscountId"  TEXT;
  END IF;
END $$;
