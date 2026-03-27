-- CreateEnum
CREATE TYPE "LabelElementType" AS ENUM ('TEXT', 'BARCODE', 'QR', 'IMAGE', 'LINE');

-- CreateEnum
CREATE TYPE "PrinterType" AS ENUM ('THERMAL', 'ZEBRA', 'A4', 'INKJET');

-- CreateTable
CREATE TABLE "LabelTemplate" (
    "id" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "widthMm" DECIMAL(8,2) NOT NULL,
    "heightMm" DECIMAL(8,2) NOT NULL,
    "dpi" INTEGER NOT NULL DEFAULT 203,
    "orientation" TEXT NOT NULL DEFAULT 'portrait',
    "bgColor" TEXT NOT NULL DEFAULT '#ffffff',
    "isDefault" BOOLEAN NOT NULL DEFAULT false,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "deletedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "LabelTemplate_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "LabelElement" (
    "id" TEXT NOT NULL,
    "templateId" TEXT NOT NULL,
    "type" "LabelElementType" NOT NULL,
    "label" TEXT NOT NULL DEFAULT '',
    "fieldKey" TEXT NOT NULL DEFAULT '',
    "x" DECIMAL(8,2) NOT NULL,
    "y" DECIMAL(8,2) NOT NULL,
    "width" DECIMAL(8,2) NOT NULL,
    "height" DECIMAL(8,2) NOT NULL,
    "fontSize" INTEGER NOT NULL DEFAULT 8,
    "fontWeight" TEXT NOT NULL DEFAULT 'normal',
    "align" TEXT NOT NULL DEFAULT 'left',
    "visible" BOOLEAN NOT NULL DEFAULT true,
    "sortOrder" INTEGER NOT NULL DEFAULT 0,
    "configJson" TEXT NOT NULL DEFAULT '{}',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "LabelElement_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PrinterProfile" (
    "id" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "type" "PrinterType" NOT NULL DEFAULT 'THERMAL',
    "dpi" INTEGER NOT NULL DEFAULT 203,
    "pageWidthMm" DECIMAL(8,2) NOT NULL DEFAULT 210,
    "pageHeightMm" DECIMAL(8,2) NOT NULL DEFAULT 297,
    "marginTopMm" DECIMAL(8,2) NOT NULL DEFAULT 5,
    "marginLeftMm" DECIMAL(8,2) NOT NULL DEFAULT 5,
    "marginRightMm" DECIMAL(8,2) NOT NULL DEFAULT 5,
    "marginBottomMm" DECIMAL(8,2) NOT NULL DEFAULT 5,
    "gapHMm" DECIMAL(8,2) NOT NULL DEFAULT 2,
    "gapVMm" DECIMAL(8,2) NOT NULL DEFAULT 2,
    "columns" INTEGER NOT NULL DEFAULT 1,
    "isDefault" BOOLEAN NOT NULL DEFAULT false,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "deletedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "PrinterProfile_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "LabelTemplate_jewelryId_idx" ON "LabelTemplate"("jewelryId");
CREATE INDEX "LabelTemplate_deletedAt_idx" ON "LabelTemplate"("deletedAt");
CREATE INDEX "LabelElement_templateId_idx" ON "LabelElement"("templateId");
CREATE INDEX "PrinterProfile_jewelryId_idx" ON "PrinterProfile"("jewelryId");
CREATE INDEX "PrinterProfile_deletedAt_idx" ON "PrinterProfile"("deletedAt");

-- AddForeignKey
ALTER TABLE "LabelTemplate" ADD CONSTRAINT "LabelTemplate_jewelryId_fkey" FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "LabelElement" ADD CONSTRAINT "LabelElement_templateId_fkey" FOREIGN KEY ("templateId") REFERENCES "LabelTemplate"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "PrinterProfile" ADD CONSTRAINT "PrinterProfile_jewelryId_fkey" FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;
