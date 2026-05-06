-- AlterTable
ALTER TABLE "Article" ALTER COLUMN "barcodeSource" SET DEFAULT 'SKU';

-- AlterTable
ALTER TABLE "ArticleVariant" ALTER COLUMN "barcodeSource" SET DEFAULT 'SKU';
