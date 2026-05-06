-- CreateEnum
CREATE TYPE "SalesChannelAdjustmentType" AS ENUM ('PERCENTAGE', 'FIXED');

-- AlterTable
ALTER TABLE "Sale" ADD COLUMN     "channelId" TEXT,
ADD COLUMN     "channelSnapshot" JSONB;

-- CreateTable
CREATE TABLE "SalesChannel" (
    "id" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "code" TEXT NOT NULL DEFAULT '',
    "adjustmentType" "SalesChannelAdjustmentType" NOT NULL,
    "adjustmentValue" DECIMAL(14,4) NOT NULL,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "isFavorite" BOOLEAN NOT NULL DEFAULT false,
    "sortOrder" INTEGER NOT NULL DEFAULT 0,
    "notes" TEXT NOT NULL DEFAULT '',
    "deletedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SalesChannel_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "SalesChannel_jewelryId_idx" ON "SalesChannel"("jewelryId");

-- CreateIndex
CREATE INDEX "SalesChannel_jewelryId_deletedAt_idx" ON "SalesChannel"("jewelryId", "deletedAt");

-- CreateIndex
CREATE INDEX "SalesChannel_jewelryId_isActive_idx" ON "SalesChannel"("jewelryId", "isActive");

-- CreateIndex
CREATE UNIQUE INDEX "SalesChannel_jewelryId_code_key" ON "SalesChannel"("jewelryId", "code");

-- CreateIndex
CREATE INDEX "Sale_channelId_idx" ON "Sale"("channelId");

-- AddForeignKey
ALTER TABLE "Sale" ADD CONSTRAINT "Sale_channelId_fkey" FOREIGN KEY ("channelId") REFERENCES "SalesChannel"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SalesChannel" ADD CONSTRAINT "SalesChannel_jewelryId_fkey" FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;
