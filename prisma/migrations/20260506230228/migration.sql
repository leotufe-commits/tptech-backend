-- CreateEnum
CREATE TYPE "ReceiptType" AS ENUM ('QUOTE', 'INVOICE', 'DELIVERY_NOTE', 'CREDIT_NOTE', 'DEBIT_NOTE');

-- CreateEnum
CREATE TYPE "ReceiptDirection" AS ENUM ('OUTBOUND', 'INBOUND');

-- CreateEnum
CREATE TYPE "ReceiptStatus" AS ENUM ('DRAFT', 'ISSUED', 'VOIDED');

-- CreateEnum
CREATE TYPE "AccountMovementKind" AS ENUM ('DEBIT', 'CREDIT');

-- CreateEnum
CREATE TYPE "AccountMovementSource" AS ENUM ('RECEIPT', 'PAYMENT_ALLOCATION');

-- CreateTable
CREATE TABLE "ReceiptSeries" (
    "id" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "type" "ReceiptType" NOT NULL,
    "direction" "ReceiptDirection" NOT NULL,
    "prefix" TEXT NOT NULL DEFAULT '',
    "pointOfSale" TEXT NOT NULL DEFAULT '0001',
    "nextNumber" INTEGER NOT NULL DEFAULT 1,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "deletedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ReceiptSeries_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Receipt" (
    "id" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "seriesId" TEXT NOT NULL,
    "code" TEXT NOT NULL,
    "type" "ReceiptType" NOT NULL,
    "direction" "ReceiptDirection" NOT NULL,
    "status" "ReceiptStatus" NOT NULL DEFAULT 'DRAFT',
    "saleId" TEXT,
    "purchaseId" TEXT,
    "correctedReceiptId" TEXT,
    "counterpartyId" TEXT,
    "pricingSnapshot" JSONB NOT NULL,
    "currencySnapshot" JSONB NOT NULL,
    "currencyCode" TEXT NOT NULL DEFAULT '',
    "currencyRate" DECIMAL(18,8) NOT NULL DEFAULT 1,
    "subtotal" DECIMAL(14,2) NOT NULL DEFAULT 0,
    "discountAmount" DECIMAL(14,2) NOT NULL DEFAULT 0,
    "taxAmount" DECIMAL(14,2) NOT NULL DEFAULT 0,
    "total" DECIMAL(14,2) NOT NULL DEFAULT 0,
    "totalBase" DECIMAL(14,2) NOT NULL DEFAULT 0,
    "issueDate" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "dueDate" TIMESTAMP(3),
    "issuedAt" TIMESTAMP(3),
    "voidedAt" TIMESTAMP(3),
    "voidReason" TEXT NOT NULL DEFAULT '',
    "notes" TEXT NOT NULL DEFAULT '',
    "issuedById" TEXT,
    "voidedById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Receipt_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ReceiptLine" (
    "id" TEXT NOT NULL,
    "receiptId" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "pricingSnapshot" JSONB NOT NULL,
    "articleId" TEXT,
    "variantId" TEXT,
    "itemKind" TEXT NOT NULL,
    "name" TEXT NOT NULL DEFAULT '',
    "code" TEXT NOT NULL DEFAULT '',
    "sku" TEXT NOT NULL DEFAULT '',
    "barcode" TEXT NOT NULL DEFAULT '',
    "quantity" DECIMAL(14,4) NOT NULL,
    "unitPrice" DECIMAL(14,4) NOT NULL,
    "subtotal" DECIMAL(14,2) NOT NULL,
    "discountAmount" DECIMAL(14,2) NOT NULL DEFAULT 0,
    "lineTotal" DECIMAL(14,2) NOT NULL,
    "taxAmount" DECIMAL(14,2) NOT NULL DEFAULT 0,
    "totalWithTax" DECIMAL(14,2) NOT NULL,
    "totalCost" DECIMAL(14,2),
    "totalMargin" DECIMAL(14,2),
    "sortOrder" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ReceiptLine_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CurrentAccountMovement" (
    "id" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "entityId" TEXT NOT NULL,
    "kind" "AccountMovementKind" NOT NULL,
    "source" "AccountMovementSource" NOT NULL,
    "receiptId" TEXT,
    "paymentAllocationId" TEXT,
    "amountBase" DECIMAL(14,2) NOT NULL,
    "amountOriginal" DECIMAL(14,2) NOT NULL,
    "currencySnapshot" JSONB NOT NULL,
    "currencyCode" TEXT NOT NULL DEFAULT '',
    "currencyRate" DECIMAL(18,8) NOT NULL,
    "movementDate" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "notes" TEXT NOT NULL DEFAULT '',

    CONSTRAINT "CurrentAccountMovement_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ReceiptSeries_jewelryId_idx" ON "ReceiptSeries"("jewelryId");

-- CreateIndex
CREATE INDEX "ReceiptSeries_jewelryId_type_direction_idx" ON "ReceiptSeries"("jewelryId", "type", "direction");

-- CreateIndex
CREATE UNIQUE INDEX "ReceiptSeries_jewelryId_type_direction_prefix_pointOfSale_key" ON "ReceiptSeries"("jewelryId", "type", "direction", "prefix", "pointOfSale");

-- CreateIndex
CREATE INDEX "Receipt_jewelryId_type_idx" ON "Receipt"("jewelryId", "type");

-- CreateIndex
CREATE INDEX "Receipt_jewelryId_status_idx" ON "Receipt"("jewelryId", "status");

-- CreateIndex
CREATE INDEX "Receipt_jewelryId_issueDate_idx" ON "Receipt"("jewelryId", "issueDate");

-- CreateIndex
CREATE INDEX "Receipt_counterpartyId_idx" ON "Receipt"("counterpartyId");

-- CreateIndex
CREATE INDEX "Receipt_saleId_idx" ON "Receipt"("saleId");

-- CreateIndex
CREATE INDEX "Receipt_purchaseId_idx" ON "Receipt"("purchaseId");

-- CreateIndex
CREATE INDEX "Receipt_correctedReceiptId_idx" ON "Receipt"("correctedReceiptId");

-- CreateIndex
CREATE UNIQUE INDEX "Receipt_jewelryId_seriesId_code_key" ON "Receipt"("jewelryId", "seriesId", "code");

-- CreateIndex
CREATE INDEX "ReceiptLine_receiptId_idx" ON "ReceiptLine"("receiptId");

-- CreateIndex
CREATE INDEX "ReceiptLine_articleId_idx" ON "ReceiptLine"("articleId");

-- CreateIndex
CREATE INDEX "ReceiptLine_variantId_idx" ON "ReceiptLine"("variantId");

-- CreateIndex
CREATE INDEX "ReceiptLine_jewelryId_idx" ON "ReceiptLine"("jewelryId");

-- CreateIndex
CREATE INDEX "CurrentAccountMovement_jewelryId_entityId_movementDate_idx" ON "CurrentAccountMovement"("jewelryId", "entityId", "movementDate");

-- CreateIndex
CREATE INDEX "CurrentAccountMovement_receiptId_idx" ON "CurrentAccountMovement"("receiptId");

-- CreateIndex
CREATE INDEX "CurrentAccountMovement_paymentAllocationId_idx" ON "CurrentAccountMovement"("paymentAllocationId");

-- AddForeignKey
ALTER TABLE "ReceiptSeries" ADD CONSTRAINT "ReceiptSeries_jewelryId_fkey" FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Receipt" ADD CONSTRAINT "Receipt_jewelryId_fkey" FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Receipt" ADD CONSTRAINT "Receipt_seriesId_fkey" FOREIGN KEY ("seriesId") REFERENCES "ReceiptSeries"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Receipt" ADD CONSTRAINT "Receipt_saleId_fkey" FOREIGN KEY ("saleId") REFERENCES "Sale"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Receipt" ADD CONSTRAINT "Receipt_purchaseId_fkey" FOREIGN KEY ("purchaseId") REFERENCES "Purchase"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Receipt" ADD CONSTRAINT "Receipt_correctedReceiptId_fkey" FOREIGN KEY ("correctedReceiptId") REFERENCES "Receipt"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Receipt" ADD CONSTRAINT "Receipt_counterpartyId_fkey" FOREIGN KEY ("counterpartyId") REFERENCES "CommercialEntity"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Receipt" ADD CONSTRAINT "Receipt_issuedById_fkey" FOREIGN KEY ("issuedById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Receipt" ADD CONSTRAINT "Receipt_voidedById_fkey" FOREIGN KEY ("voidedById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ReceiptLine" ADD CONSTRAINT "ReceiptLine_receiptId_fkey" FOREIGN KEY ("receiptId") REFERENCES "Receipt"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ReceiptLine" ADD CONSTRAINT "ReceiptLine_articleId_fkey" FOREIGN KEY ("articleId") REFERENCES "Article"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ReceiptLine" ADD CONSTRAINT "ReceiptLine_variantId_fkey" FOREIGN KEY ("variantId") REFERENCES "ArticleVariant"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ReceiptLine" ADD CONSTRAINT "ReceiptLine_jewelryId_fkey" FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CurrentAccountMovement" ADD CONSTRAINT "CurrentAccountMovement_jewelryId_fkey" FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CurrentAccountMovement" ADD CONSTRAINT "CurrentAccountMovement_entityId_fkey" FOREIGN KEY ("entityId") REFERENCES "CommercialEntity"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CurrentAccountMovement" ADD CONSTRAINT "CurrentAccountMovement_receiptId_fkey" FOREIGN KEY ("receiptId") REFERENCES "Receipt"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
