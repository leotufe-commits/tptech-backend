-- DropIndex
DROP INDEX "Article_jewelryId_costCalculationMode_idx";

-- AlterTable
ALTER TABLE "ArticleAttributeDefOption" ADD COLUMN     "codeExtension" TEXT NOT NULL DEFAULT '';
