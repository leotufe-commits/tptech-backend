-- Add new CatalogType values for article brand, manufacturer and unit of measure
ALTER TYPE "CatalogType" ADD VALUE IF NOT EXISTS 'ARTICLE_BRAND';
ALTER TYPE "CatalogType" ADD VALUE IF NOT EXISTS 'ARTICLE_MANUFACTURER';
ALTER TYPE "CatalogType" ADD VALUE IF NOT EXISTS 'UNIT_OF_MEASURE';
