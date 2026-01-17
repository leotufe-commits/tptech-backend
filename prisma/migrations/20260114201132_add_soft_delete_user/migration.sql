-- AlterTable
ALTER TABLE "User" ADD COLUMN     "deletedAt" TIMESTAMP(3);

-- CreateIndex
CREATE INDEX "User_jewelryId_deletedAt_idx" ON "User"("jewelryId", "deletedAt");
