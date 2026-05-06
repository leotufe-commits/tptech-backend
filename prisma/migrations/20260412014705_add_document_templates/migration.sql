-- CreateEnum
CREATE TYPE "DocumentKind" AS ENUM ('PRESUPUESTO', 'FACTURA', 'REMITO', 'ORDEN_COMPRA', 'MOVIMIENTO_STOCK');

-- CreateTable
CREATE TABLE "DocumentTemplate" (
    "id" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "kind" "DocumentKind" NOT NULL,
    "name" TEXT NOT NULL DEFAULT '',
    "isDefault" BOOLEAN NOT NULL DEFAULT true,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "headerLogoEnabled" BOOLEAN NOT NULL DEFAULT true,
    "headerShowName" BOOLEAN NOT NULL DEFAULT true,
    "headerShowLegalName" BOOLEAN NOT NULL DEFAULT false,
    "headerShowCuit" BOOLEAN NOT NULL DEFAULT true,
    "headerShowAddress" BOOLEAN NOT NULL DEFAULT true,
    "headerShowPhone" BOOLEAN NOT NULL DEFAULT true,
    "headerShowEmail" BOOLEAN NOT NULL DEFAULT false,
    "headerShowWebsite" BOOLEAN NOT NULL DEFAULT false,
    "headerCustomText" TEXT NOT NULL DEFAULT '',
    "pageSize" TEXT NOT NULL DEFAULT 'A4',
    "orientation" TEXT NOT NULL DEFAULT 'portrait',
    "marginTop" DECIMAL(6,2) NOT NULL DEFAULT 15,
    "marginRight" DECIMAL(6,2) NOT NULL DEFAULT 15,
    "marginBottom" DECIMAL(6,2) NOT NULL DEFAULT 20,
    "marginLeft" DECIMAL(6,2) NOT NULL DEFAULT 15,
    "fontFamily" TEXT NOT NULL DEFAULT 'inter',
    "fontSizeBase" INTEGER NOT NULL DEFAULT 10,
    "accentColor" TEXT NOT NULL DEFAULT '#1a1a1a',
    "tableStyle" TEXT NOT NULL DEFAULT 'bordered',
    "currencyShowSymbol" BOOLEAN NOT NULL DEFAULT true,
    "currencyShowRate" BOOLEAN NOT NULL DEFAULT false,
    "currencyDecimals" INTEGER NOT NULL DEFAULT 2,
    "pricesIncludeTax" BOOLEAN NOT NULL DEFAULT false,
    "footerText" TEXT NOT NULL DEFAULT '',
    "footerLegalText" TEXT NOT NULL DEFAULT '',
    "footerBankData" TEXT NOT NULL DEFAULT '',
    "footerTerms" TEXT NOT NULL DEFAULT '',
    "footerShowPageNumbers" BOOLEAN NOT NULL DEFAULT true,
    "footerPageFormat" TEXT NOT NULL DEFAULT 'page_of_total',
    "footerPagePosition" TEXT NOT NULL DEFAULT 'bottom_right',
    "sections" TEXT NOT NULL DEFAULT '{}',
    "columns" TEXT NOT NULL DEFAULT '[]',
    "columnsVersion" INTEGER NOT NULL DEFAULT 1,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),

    CONSTRAINT "DocumentTemplate_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "DocumentTemplate_jewelryId_idx" ON "DocumentTemplate"("jewelryId");

-- CreateIndex
CREATE UNIQUE INDEX "DocumentTemplate_jewelryId_kind_key" ON "DocumentTemplate"("jewelryId", "kind");

-- AddForeignKey
ALTER TABLE "DocumentTemplate" ADD CONSTRAINT "DocumentTemplate_jewelryId_fkey" FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;
