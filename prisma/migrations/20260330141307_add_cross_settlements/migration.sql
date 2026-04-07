-- CreateEnum
CREATE TYPE "CrossSettlementStatus" AS ENUM ('CONFIRMED', 'VOIDED');

-- CreateEnum
CREATE TYPE "CrossSettlementComponentType" AS ENUM ('MONEY', 'METAL');

-- AlterEnum
ALTER TYPE "BalanceEntryType" ADD VALUE 'CROSS_SETTLEMENT';

-- CreateTable
CREATE TABLE "CrossSettlement" (
    "id" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "supplierId" TEXT NOT NULL,
    "targetPurchaseId" TEXT,
    "status" "CrossSettlementStatus" NOT NULL DEFAULT 'CONFIRMED',
    "fromComponentType" "CrossSettlementComponentType" NOT NULL,
    "fromCurrency" TEXT,
    "fromMetalId" TEXT,
    "fromVariantId" TEXT,
    "fromGramsOriginal" DECIMAL(14,6),
    "fromPurity" DECIMAL(10,6),
    "fromGramsPure" DECIMAL(14,6),
    "fromAmount" DECIMAL(14,2),
    "toComponentType" "CrossSettlementComponentType" NOT NULL,
    "toCurrency" TEXT,
    "toMetalId" TEXT,
    "toVariantId" TEXT,
    "toGramsOriginal" DECIMAL(14,6),
    "toPurity" DECIMAL(10,6),
    "toGramsPure" DECIMAL(14,6),
    "toAmount" DECIMAL(14,2),
    "fxRate" DECIMAL(18,8),
    "metalQuotePerGram" DECIMAL(18,8),
    "quoteCurrency" TEXT,
    "notes" TEXT NOT NULL DEFAULT '',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "confirmedAt" TIMESTAMP(3),
    "voidedAt" TIMESTAMP(3),
    "voidReason" TEXT NOT NULL DEFAULT '',
    "createdById" TEXT,
    "voidedById" TEXT,

    CONSTRAINT "CrossSettlement_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "CrossSettlement_jewelryId_idx" ON "CrossSettlement"("jewelryId");

-- CreateIndex
CREATE INDEX "CrossSettlement_supplierId_idx" ON "CrossSettlement"("supplierId");

-- CreateIndex
CREATE INDEX "CrossSettlement_targetPurchaseId_idx" ON "CrossSettlement"("targetPurchaseId");

-- CreateIndex
CREATE INDEX "CrossSettlement_createdAt_idx" ON "CrossSettlement"("createdAt");

-- CreateIndex
CREATE INDEX "CrossSettlement_voidedAt_idx" ON "CrossSettlement"("voidedAt");

-- AddForeignKey
ALTER TABLE "CrossSettlement" ADD CONSTRAINT "CrossSettlement_supplierId_fkey" FOREIGN KEY ("supplierId") REFERENCES "CommercialEntity"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CrossSettlement" ADD CONSTRAINT "CrossSettlement_targetPurchaseId_fkey" FOREIGN KEY ("targetPurchaseId") REFERENCES "Purchase"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CrossSettlement" ADD CONSTRAINT "CrossSettlement_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CrossSettlement" ADD CONSTRAINT "CrossSettlement_voidedById_fkey" FOREIGN KEY ("voidedById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
