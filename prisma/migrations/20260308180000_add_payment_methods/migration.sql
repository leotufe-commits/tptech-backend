-- CreateEnum
CREATE TYPE "PaymentMethodType" AS ENUM ('CASH', 'DEBIT_CARD', 'CREDIT_CARD', 'TRANSFER', 'QR', 'OTHER');
CREATE TYPE "PaymentAdjustmentType" AS ENUM ('NONE', 'PERCENTAGE', 'FIXED_AMOUNT');

-- CreateTable
CREATE TABLE "PaymentMethod" (
    "id" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "code" TEXT NOT NULL DEFAULT '',
    "type" "PaymentMethodType" NOT NULL DEFAULT 'OTHER',
    "adjustmentType" "PaymentAdjustmentType" NOT NULL DEFAULT 'NONE',
    "adjustmentValue" DECIMAL(10,4),
    "isFavorite" BOOLEAN NOT NULL DEFAULT false,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "sortOrder" INTEGER NOT NULL DEFAULT 0,
    "notes" TEXT NOT NULL DEFAULT '',
    "deletedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "PaymentMethod_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PaymentInstallmentPlan" (
    "id" TEXT NOT NULL,
    "paymentMethodId" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "installments" INTEGER NOT NULL,
    "interestRate" DECIMAL(10,4) NOT NULL,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "sortOrder" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "PaymentInstallmentPlan_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "PaymentMethod_jewelryId_idx" ON "PaymentMethod"("jewelryId");
CREATE INDEX "PaymentMethod_jewelryId_isActive_idx" ON "PaymentMethod"("jewelryId", "isActive");
CREATE INDEX "PaymentMethod_jewelryId_isFavorite_idx" ON "PaymentMethod"("jewelryId", "isFavorite");
CREATE INDEX "PaymentMethod_jewelryId_deletedAt_idx" ON "PaymentMethod"("jewelryId", "deletedAt");
CREATE INDEX "PaymentMethod_deletedAt_idx" ON "PaymentMethod"("deletedAt");
CREATE INDEX "PaymentInstallmentPlan_paymentMethodId_idx" ON "PaymentInstallmentPlan"("paymentMethodId");
CREATE INDEX "PaymentInstallmentPlan_jewelryId_idx" ON "PaymentInstallmentPlan"("jewelryId");

-- AddForeignKey
ALTER TABLE "PaymentMethod" ADD CONSTRAINT "PaymentMethod_jewelryId_fkey" FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PaymentInstallmentPlan" ADD CONSTRAINT "PaymentInstallmentPlan_paymentMethodId_fkey" FOREIGN KEY ("paymentMethodId") REFERENCES "PaymentMethod"("id") ON DELETE CASCADE ON UPDATE CASCADE;
