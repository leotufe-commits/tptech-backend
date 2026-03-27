-- DropIndex
DROP INDEX "CommercialEntity_mergedIntoEntityId_idx";

-- AlterTable
ALTER TABLE "EntityMermaOverride" ALTER COLUMN "updatedAt" DROP DEFAULT;
