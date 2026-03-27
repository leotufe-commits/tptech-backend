-- CreateEnum
CREATE TYPE "BarcodeType" AS ENUM ('CODE128', 'EAN13', 'QR');

-- AlterTable Article: add commercial fields
ALTER TABLE "Article"
  ADD COLUMN "sku"                 TEXT NOT NULL DEFAULT '',
  ADD COLUMN "barcode"             TEXT,
  ADD COLUMN "barcodeType"         "BarcodeType" NOT NULL DEFAULT 'CODE128',
  ADD COLUMN "brand"               TEXT NOT NULL DEFAULT '',
  ADD COLUMN "manufacturer"        TEXT NOT NULL DEFAULT '',
  ADD COLUMN "supplierCode"        TEXT NOT NULL DEFAULT '',
  ADD COLUMN "preferredSupplierId" TEXT,
  ADD COLUMN "costPrice"           DECIMAL(14,4),
  ADD COLUMN "salePrice"           DECIMAL(14,4),
  ADD COLUMN "sellWithoutVariants" BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN "isReturnable"        BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN "showInStore"         BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN "unitOfMeasure"       TEXT NOT NULL DEFAULT '',
  ADD COLUMN "reorderPoint"        DECIMAL(14,4);

-- AlterTable ArticleVariant: add commercial fields
ALTER TABLE "ArticleVariant"
  ADD COLUMN "sku"         TEXT NOT NULL DEFAULT '',
  ADD COLUMN "barcode"     TEXT,
  ADD COLUMN "barcodeType" "BarcodeType" NOT NULL DEFAULT 'CODE128',
  ADD COLUMN "costPrice"   DECIMAL(14,4),
  ADD COLUMN "notes"       TEXT NOT NULL DEFAULT '';

-- CreateIndex unique barcode per tenant (NULLs excluded by PostgreSQL)
CREATE UNIQUE INDEX "Article_jewelryId_barcode_key"
  ON "Article"("jewelryId", "barcode")
  WHERE "barcode" IS NOT NULL;

CREATE UNIQUE INDEX "ArticleVariant_jewelryId_barcode_key"
  ON "ArticleVariant"("jewelryId", "barcode")
  WHERE "barcode" IS NOT NULL;

-- CreateIndex additional performance indexes
CREATE INDEX "Article_preferredSupplierId_idx" ON "Article"("preferredSupplierId");
CREATE INDEX "Article_jewelryId_articleType_idx" ON "Article"("jewelryId", "articleType");
CREATE INDEX "Article_jewelryId_sku_idx" ON "Article"("jewelryId", "sku");
CREATE INDEX "Article_jewelryId_barcode_idx" ON "Article"("jewelryId", "barcode");
CREATE INDEX "ArticleVariant_jewelryId_sku_idx" ON "ArticleVariant"("jewelryId", "sku");
CREATE INDEX "ArticleVariant_jewelryId_barcode_idx" ON "ArticleVariant"("jewelryId", "barcode");

-- AddForeignKey Article.preferredSupplierId → CommercialEntity
ALTER TABLE "Article"
  ADD CONSTRAINT "Article_preferredSupplierId_fkey"
  FOREIGN KEY ("preferredSupplierId")
  REFERENCES "CommercialEntity"("id")
  ON DELETE SET NULL ON UPDATE CASCADE;
