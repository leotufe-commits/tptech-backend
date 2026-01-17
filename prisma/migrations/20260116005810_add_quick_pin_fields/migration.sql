-- AlterTable
ALTER TABLE "User" ADD COLUMN     "quickPinFailedCount" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "quickPinHash" TEXT,
ADD COLUMN     "quickPinLockedUntil" TIMESTAMP(3),
ADD COLUMN     "quickPinUpdatedAt" TIMESTAMP(3);

-- CreateIndex
CREATE INDEX "User_quickPinUpdatedAt_idx" ON "User"("quickPinUpdatedAt");
