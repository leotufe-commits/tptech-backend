-- CreateEnum
CREATE TYPE "TaxType" AS ENUM ('IVA', 'INTERNAL', 'PERCEPTION', 'RETENTION', 'OTHER');
CREATE TYPE "TaxCalculationType" AS ENUM ('PERCENTAGE', 'FIXED_AMOUNT', 'PERCENTAGE_PLUS_FIXED');
CREATE TYPE "TaxApplyOn" AS ENUM ('TOTAL', 'METAL', 'HECHURA', 'METAL_Y_HECHURA', 'SUBTOTAL_AFTER_DISCOUNT', 'SUBTOTAL_BEFORE_DISCOUNT');

-- CreateTable
CREATE TABLE "Tax" (
    "id" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "code" TEXT NOT NULL DEFAULT '',
    "taxType" "TaxType" NOT NULL DEFAULT 'OTHER',
    "calculationType" "TaxCalculationType" NOT NULL DEFAULT 'PERCENTAGE',
    "rate" DECIMAL(10,4),
    "fixedAmount" DECIMAL(18,2),
    "applyOn" "TaxApplyOn" NOT NULL DEFAULT 'TOTAL',
    "includedInPrice" BOOLEAN NOT NULL DEFAULT false,
    "validFrom" TIMESTAMP(3),
    "validTo" TIMESTAMP(3),
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "sortOrder" INTEGER NOT NULL DEFAULT 0,
    "notes" TEXT NOT NULL DEFAULT '',
    "deletedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Tax_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "Tax_jewelryId_idx" ON "Tax"("jewelryId");
CREATE INDEX "Tax_jewelryId_isActive_idx" ON "Tax"("jewelryId", "isActive");
CREATE INDEX "Tax_jewelryId_deletedAt_idx" ON "Tax"("jewelryId", "deletedAt");
CREATE INDEX "Tax_deletedAt_idx" ON "Tax"("deletedAt");

-- AddForeignKey
ALTER TABLE "Tax" ADD CONSTRAINT "Tax_jewelryId_fkey" FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;
