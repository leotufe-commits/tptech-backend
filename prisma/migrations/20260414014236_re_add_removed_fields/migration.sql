-- AlterTable
ALTER TABLE "ArticleVariant" ADD COLUMN     "defaultQuantity" DECIMAL(14,4),
ADD COLUMN     "maxSaleQuantity" DECIMAL(14,4),
ADD COLUMN     "minSaleQuantity" DECIMAL(14,4);
