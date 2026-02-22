-- AlterTable
ALTER TABLE "Metal" ADD COLUMN     "sortOrder" INTEGER NOT NULL DEFAULT 0;

-- CreateTable
CREATE TABLE "MetalRefValueHistory" (
    "id" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "metalId" TEXT NOT NULL,
    "referenceValue" DECIMAL(18,6) NOT NULL,
    "effectiveAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdById" TEXT,

    CONSTRAINT "MetalRefValueHistory_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "MetalRefValueHistory_jewelryId_metalId_effectiveAt_idx" ON "MetalRefValueHistory"("jewelryId", "metalId", "effectiveAt");

-- CreateIndex
CREATE INDEX "MetalRefValueHistory_metalId_effectiveAt_idx" ON "MetalRefValueHistory"("metalId", "effectiveAt");

-- CreateIndex
CREATE INDEX "MetalRefValueHistory_createdById_idx" ON "MetalRefValueHistory"("createdById");

-- CreateIndex
CREATE INDEX "Metal_jewelryId_sortOrder_idx" ON "Metal"("jewelryId", "sortOrder");

-- AddForeignKey
ALTER TABLE "MetalRefValueHistory" ADD CONSTRAINT "MetalRefValueHistory_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MetalRefValueHistory" ADD CONSTRAINT "MetalRefValueHistory_metalId_fkey" FOREIGN KEY ("metalId") REFERENCES "Metal"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MetalRefValueHistory" ADD CONSTRAINT "MetalRefValueHistory_jewelryId_fkey" FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;
