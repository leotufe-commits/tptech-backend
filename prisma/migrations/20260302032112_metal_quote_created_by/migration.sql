-- AlterTable
ALTER TABLE "MetalQuote" ADD COLUMN     "createdById" TEXT;

-- CreateTable
CREATE TABLE "MetalVariantValueHistory" (
    "id" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "metalId" TEXT NOT NULL,
    "variantId" TEXT NOT NULL,
    "referenceValue" DECIMAL(18,6) NOT NULL,
    "purity" DECIMAL(6,4) NOT NULL,
    "buyFactor" DECIMAL(12,6) NOT NULL,
    "saleFactor" DECIMAL(12,6) NOT NULL,
    "purchasePriceOverride" DECIMAL(18,6),
    "salePriceOverride" DECIMAL(18,6),
    "pricingMode" "VariantPricingMode" NOT NULL,
    "suggestedPrice" DECIMAL(18,6) NOT NULL,
    "finalPurchasePrice" DECIMAL(18,6) NOT NULL,
    "finalSalePrice" DECIMAL(18,6) NOT NULL,
    "effectiveAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdById" TEXT,

    CONSTRAINT "MetalVariantValueHistory_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "MetalVariantValueHistory_jewelryId_variantId_effectiveAt_idx" ON "MetalVariantValueHistory"("jewelryId", "variantId", "effectiveAt");

-- CreateIndex
CREATE INDEX "MetalVariantValueHistory_variantId_effectiveAt_idx" ON "MetalVariantValueHistory"("variantId", "effectiveAt");

-- CreateIndex
CREATE INDEX "MetalVariantValueHistory_metalId_effectiveAt_idx" ON "MetalVariantValueHistory"("metalId", "effectiveAt");

-- CreateIndex
CREATE INDEX "MetalVariantValueHistory_createdById_idx" ON "MetalVariantValueHistory"("createdById");

-- CreateIndex
CREATE INDEX "MetalQuote_createdById_idx" ON "MetalQuote"("createdById");

-- AddForeignKey
ALTER TABLE "MetalQuote" ADD CONSTRAINT "MetalQuote_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MetalVariantValueHistory" ADD CONSTRAINT "MetalVariantValueHistory_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MetalVariantValueHistory" ADD CONSTRAINT "MetalVariantValueHistory_jewelryId_fkey" FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MetalVariantValueHistory" ADD CONSTRAINT "MetalVariantValueHistory_metalId_fkey" FOREIGN KEY ("metalId") REFERENCES "Metal"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MetalVariantValueHistory" ADD CONSTRAINT "MetalVariantValueHistory_variantId_fkey" FOREIGN KEY ("variantId") REFERENCES "MetalVariant"("id") ON DELETE CASCADE ON UPDATE CASCADE;
