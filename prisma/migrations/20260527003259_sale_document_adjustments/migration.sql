-- AlterTable
ALTER TABLE "Sale" ADD COLUMN     "globalDiscountType" TEXT,
ADD COLUMN     "globalDiscountValue" DECIMAL(14,4),
ADD COLUMN     "paymentInstallments" INTEGER,
ADD COLUMN     "paymentMethodId" TEXT,
ADD COLUMN     "shippingAmount" DECIMAL(14,2);

-- CreateIndex
CREATE INDEX "Sale_paymentMethodId_idx" ON "Sale"("paymentMethodId");

-- AddForeignKey
ALTER TABLE "Sale" ADD CONSTRAINT "Sale_paymentMethodId_fkey" FOREIGN KEY ("paymentMethodId") REFERENCES "PaymentMethod"("id") ON DELETE SET NULL ON UPDATE CASCADE;
