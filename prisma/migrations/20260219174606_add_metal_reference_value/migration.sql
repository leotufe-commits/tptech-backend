-- DropIndex
DROP INDEX "Metal_jewelryId_symbol_key";

-- AlterTable
ALTER TABLE "Metal" ADD COLUMN     "referenceValue" DECIMAL(18,6) NOT NULL DEFAULT 0;
