/*
  Warnings:

  - You are about to drop the column `paymentTermDays` on the `CommercialEntity` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "CommercialEntity" DROP COLUMN "paymentTermDays",
ADD COLUMN     "paymentTermId" TEXT;

-- CreateTable
CREATE TABLE "PaymentTerm" (
    "id" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "days" INTEGER,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "sortOrder" INTEGER NOT NULL DEFAULT 0,
    "deletedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "PaymentTerm_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "PaymentTerm_jewelryId_idx" ON "PaymentTerm"("jewelryId");

-- CreateIndex
CREATE INDEX "PaymentTerm_jewelryId_isActive_idx" ON "PaymentTerm"("jewelryId", "isActive");

-- CreateIndex
CREATE UNIQUE INDEX "PaymentTerm_jewelryId_name_key" ON "PaymentTerm"("jewelryId", "name");

-- CreateIndex
CREATE INDEX "CommercialEntity_paymentTermId_idx" ON "CommercialEntity"("paymentTermId");

-- AddForeignKey
ALTER TABLE "CommercialEntity" ADD CONSTRAINT "CommercialEntity_paymentTermId_fkey" FOREIGN KEY ("paymentTermId") REFERENCES "PaymentTerm"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PaymentTerm" ADD CONSTRAINT "PaymentTerm_jewelryId_fkey" FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;
