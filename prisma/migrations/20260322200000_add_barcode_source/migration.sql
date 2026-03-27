-- CreateEnum (idempotente: solo crea si no existe)
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'BarcodeSource') THEN
    CREATE TYPE "BarcodeSource" AS ENUM ('CODE', 'SKU', 'CUSTOM');
  END IF;
END $$;

-- AlterTable Article (idempotente)
ALTER TABLE "Article" ADD COLUMN IF NOT EXISTS "barcodeSource" "BarcodeSource" NOT NULL DEFAULT 'CUSTOM';

-- AlterTable ArticleVariant (idempotente)
ALTER TABLE "ArticleVariant" ADD COLUMN IF NOT EXISTS "barcodeSource" "BarcodeSource" NOT NULL DEFAULT 'CUSTOM';

-- Inferir la fuente del barcode a partir de los datos existentes
UPDATE "Article"
SET "barcodeSource" = CASE
  WHEN barcode IS NOT NULL AND barcode = code THEN 'CODE'::"BarcodeSource"
  WHEN barcode IS NOT NULL AND sku != '' AND barcode = sku THEN 'SKU'::"BarcodeSource"
  ELSE 'CUSTOM'::"BarcodeSource"
END;

UPDATE "ArticleVariant"
SET "barcodeSource" = CASE
  WHEN barcode IS NOT NULL AND barcode = code THEN 'CODE'::"BarcodeSource"
  WHEN barcode IS NOT NULL AND sku != '' AND barcode = sku THEN 'SKU'::"BarcodeSource"
  ELSE 'CUSTOM'::"BarcodeSource"
END;
