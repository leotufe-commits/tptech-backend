-- AlterTable
ALTER TABLE "ArticleMovementLine" ADD COLUMN     "snapshot" JSONB;

-- AlterTable
ALTER TABLE "InventoryMovementLine" ADD COLUMN     "snapshot" JSONB;
