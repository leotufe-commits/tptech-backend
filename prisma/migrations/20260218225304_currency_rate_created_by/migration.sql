-- AlterTable
ALTER TABLE "CurrencyRate" ADD COLUMN     "createdById" TEXT;

-- CreateIndex
CREATE INDEX "CurrencyRate_createdById_idx" ON "CurrencyRate"("createdById");

-- AddForeignKey
ALTER TABLE "CurrencyRate" ADD CONSTRAINT "CurrencyRate_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
