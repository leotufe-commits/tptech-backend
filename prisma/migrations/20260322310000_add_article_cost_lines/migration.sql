-- CreateEnum (idempotente)
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'CostLineType') THEN
    CREATE TYPE "CostLineType" AS ENUM ('METAL', 'HECHURA', 'PRODUCT', 'SERVICE', 'MANUAL');
  END IF;
END $$;

-- CreateTable (idempotente)
CREATE TABLE IF NOT EXISTS "ArticleCostLine" (
  "id"             TEXT          NOT NULL,
  "articleId"      TEXT          NOT NULL,
  "jewelryId"      TEXT          NOT NULL,
  "type"           "CostLineType" NOT NULL DEFAULT 'MANUAL',
  "label"          TEXT          NOT NULL DEFAULT '',
  "quantity"       DECIMAL(14,4) NOT NULL DEFAULT 1,
  "unitValue"      DECIMAL(18,6) NOT NULL DEFAULT 0,
  "currencyId"     TEXT,
  "mermaPercent"   DECIMAL(5,2),
  "metalVariantId" TEXT,
  "sortOrder"      INTEGER       NOT NULL DEFAULT 0,
  "createdAt"      TIMESTAMP(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt"      TIMESTAMP(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "ArticleCostLine_pkey" PRIMARY KEY ("id")
);

-- Indexes (idempotentes)
CREATE INDEX IF NOT EXISTS "ArticleCostLine_articleId_idx" ON "ArticleCostLine"("articleId");
CREATE INDEX IF NOT EXISTS "ArticleCostLine_jewelryId_idx" ON "ArticleCostLine"("jewelryId");

-- Foreign keys (idempotentes)
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'ArticleCostLine_articleId_fkey'
  ) THEN
    ALTER TABLE "ArticleCostLine"
      ADD CONSTRAINT "ArticleCostLine_articleId_fkey"
      FOREIGN KEY ("articleId") REFERENCES "Article"("id") ON DELETE CASCADE ON UPDATE CASCADE;
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'ArticleCostLine_currencyId_fkey'
  ) THEN
    ALTER TABLE "ArticleCostLine"
      ADD CONSTRAINT "ArticleCostLine_currencyId_fkey"
      FOREIGN KEY ("currencyId") REFERENCES "Currency"("id") ON DELETE SET NULL ON UPDATE CASCADE;
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'ArticleCostLine_metalVariantId_fkey'
  ) THEN
    ALTER TABLE "ArticleCostLine"
      ADD CONSTRAINT "ArticleCostLine_metalVariantId_fkey"
      FOREIGN KEY ("metalVariantId") REFERENCES "MetalVariant"("id") ON DELETE SET NULL ON UPDATE CASCADE;
  END IF;
END $$;
