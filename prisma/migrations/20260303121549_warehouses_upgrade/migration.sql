-- DropIndex
DROP INDEX "Warehouse_jewelryId_deletedAt_idx";

-- AlterTable
ALTER TABLE "Warehouse" ADD COLUMN     "code" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "notes" TEXT NOT NULL DEFAULT '';
