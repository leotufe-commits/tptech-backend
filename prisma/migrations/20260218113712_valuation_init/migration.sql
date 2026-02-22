-- CreateTable
CREATE TABLE "Currency" (
    "id" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "code" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "symbol" TEXT NOT NULL,
    "isBase" BOOLEAN NOT NULL DEFAULT false,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Currency_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CurrencyRate" (
    "id" TEXT NOT NULL,
    "currencyId" TEXT NOT NULL,
    "rate" DECIMAL(18,6) NOT NULL,
    "effectiveAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CurrencyRate_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Metal" (
    "id" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Metal_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "MetalVariant" (
    "id" TEXT NOT NULL,
    "metalId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "sku" TEXT NOT NULL,
    "purity" DECIMAL(6,4) NOT NULL,
    "isFavorite" BOOLEAN NOT NULL DEFAULT false,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "MetalVariant_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "MetalQuote" (
    "id" TEXT NOT NULL,
    "variantId" TEXT NOT NULL,
    "currencyId" TEXT NOT NULL,
    "purchasePrice" DECIMAL(18,6) NOT NULL,
    "salePrice" DECIMAL(18,6) NOT NULL,
    "effectiveAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "MetalQuote_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "Currency_jewelryId_idx" ON "Currency"("jewelryId");

-- CreateIndex
CREATE INDEX "Currency_jewelryId_isActive_idx" ON "Currency"("jewelryId", "isActive");

-- CreateIndex
CREATE INDEX "Currency_jewelryId_isBase_idx" ON "Currency"("jewelryId", "isBase");

-- CreateIndex
CREATE UNIQUE INDEX "Currency_jewelryId_code_key" ON "Currency"("jewelryId", "code");

-- CreateIndex
CREATE INDEX "CurrencyRate_currencyId_effectiveAt_idx" ON "CurrencyRate"("currencyId", "effectiveAt");

-- CreateIndex
CREATE INDEX "Metal_jewelryId_idx" ON "Metal"("jewelryId");

-- CreateIndex
CREATE INDEX "Metal_jewelryId_isActive_idx" ON "Metal"("jewelryId", "isActive");

-- CreateIndex
CREATE UNIQUE INDEX "Metal_jewelryId_name_key" ON "Metal"("jewelryId", "name");

-- CreateIndex
CREATE INDEX "MetalVariant_metalId_idx" ON "MetalVariant"("metalId");

-- CreateIndex
CREATE INDEX "MetalVariant_metalId_isActive_idx" ON "MetalVariant"("metalId", "isActive");

-- CreateIndex
CREATE INDEX "MetalVariant_metalId_isFavorite_idx" ON "MetalVariant"("metalId", "isFavorite");

-- CreateIndex
CREATE UNIQUE INDEX "MetalVariant_metalId_sku_key" ON "MetalVariant"("metalId", "sku");

-- CreateIndex
CREATE INDEX "MetalQuote_variantId_effectiveAt_idx" ON "MetalQuote"("variantId", "effectiveAt");

-- CreateIndex
CREATE INDEX "MetalQuote_currencyId_idx" ON "MetalQuote"("currencyId");

-- AddForeignKey
ALTER TABLE "Currency" ADD CONSTRAINT "Currency_jewelryId_fkey" FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CurrencyRate" ADD CONSTRAINT "CurrencyRate_currencyId_fkey" FOREIGN KEY ("currencyId") REFERENCES "Currency"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Metal" ADD CONSTRAINT "Metal_jewelryId_fkey" FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MetalVariant" ADD CONSTRAINT "MetalVariant_metalId_fkey" FOREIGN KEY ("metalId") REFERENCES "Metal"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MetalQuote" ADD CONSTRAINT "MetalQuote_variantId_fkey" FOREIGN KEY ("variantId") REFERENCES "MetalVariant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MetalQuote" ADD CONSTRAINT "MetalQuote_currencyId_fkey" FOREIGN KEY ("currencyId") REFERENCES "Currency"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
