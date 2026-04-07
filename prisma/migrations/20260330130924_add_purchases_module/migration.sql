-- CreateEnum
CREATE TYPE "PurchaseStatus" AS ENUM ('DRAFT', 'CONFIRMED', 'PARTIALLY_PAID', 'PAID', 'CANCELLED');

-- CreateEnum
CREATE TYPE "PurchasePaymentComponentType" AS ENUM ('MONEY', 'METAL');

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "BalanceEntryType" ADD VALUE 'PURCHASE_INVOICE';
ALTER TYPE "BalanceEntryType" ADD VALUE 'SUPPLIER_PAYMENT';
ALTER TYPE "BalanceEntryType" ADD VALUE 'METAL_RETURN';

-- CreateTable
CREATE TABLE "Purchase" (
    "id" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "code" TEXT NOT NULL,
    "status" "PurchaseStatus" NOT NULL DEFAULT 'DRAFT',
    "supplierId" TEXT NOT NULL,
    "supplierSnapshot" JSONB,
    "subtotal" DECIMAL(14,2) NOT NULL DEFAULT 0,
    "discountAmount" DECIMAL(14,2) NOT NULL DEFAULT 0,
    "taxAmount" DECIMAL(14,2) NOT NULL DEFAULT 0,
    "total" DECIMAL(14,2) NOT NULL DEFAULT 0,
    "paidAmount" DECIMAL(14,2) NOT NULL DEFAULT 0,
    "purchaseDate" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "confirmedAt" TIMESTAMP(3),
    "cancelledAt" TIMESTAMP(3),
    "cancelNote" TEXT NOT NULL DEFAULT '',
    "notes" TEXT NOT NULL DEFAULT '',
    "createdById" TEXT,
    "confirmedById" TEXT,
    "cancelledById" TEXT,

    CONSTRAINT "Purchase_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PurchaseLine" (
    "id" TEXT NOT NULL,
    "purchaseId" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "articleId" TEXT,
    "variantId" TEXT,
    "articleName" TEXT NOT NULL DEFAULT '',
    "variantName" TEXT NOT NULL DEFAULT '',
    "sku" TEXT NOT NULL DEFAULT '',
    "barcode" TEXT NOT NULL DEFAULT '',
    "quantity" DECIMAL(14,4) NOT NULL,
    "unitCost" DECIMAL(14,4) NOT NULL,
    "lineTotal" DECIMAL(14,2) NOT NULL,
    "breakdownSnapshot" JSONB,
    "sortOrder" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PurchaseLine_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PurchasePayment" (
    "id" TEXT NOT NULL,
    "purchaseId" TEXT,
    "jewelryId" TEXT NOT NULL,
    "supplierId" TEXT NOT NULL,
    "paymentDate" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "note" TEXT NOT NULL DEFAULT '',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdById" TEXT,
    "voidedAt" TIMESTAMP(3),
    "voidedBy" TEXT,
    "voidReason" TEXT NOT NULL DEFAULT '',

    CONSTRAINT "PurchasePayment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PurchasePaymentComponent" (
    "id" TEXT NOT NULL,
    "paymentId" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "componentType" "PurchasePaymentComponentType" NOT NULL,
    "amount" DECIMAL(14,2),
    "currency" TEXT NOT NULL DEFAULT 'ARS',
    "metalId" TEXT,
    "variantId" TEXT,
    "gramsOriginal" DECIMAL(14,6),
    "purity" DECIMAL(10,6),
    "gramsPure" DECIMAL(14,6),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PurchasePaymentComponent_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "Purchase_jewelryId_idx" ON "Purchase"("jewelryId");

-- CreateIndex
CREATE INDEX "Purchase_jewelryId_status_idx" ON "Purchase"("jewelryId", "status");

-- CreateIndex
CREATE INDEX "Purchase_jewelryId_purchaseDate_idx" ON "Purchase"("jewelryId", "purchaseDate");

-- CreateIndex
CREATE INDEX "Purchase_supplierId_idx" ON "Purchase"("supplierId");

-- CreateIndex
CREATE UNIQUE INDEX "Purchase_jewelryId_code_key" ON "Purchase"("jewelryId", "code");

-- CreateIndex
CREATE INDEX "PurchaseLine_purchaseId_idx" ON "PurchaseLine"("purchaseId");

-- CreateIndex
CREATE INDEX "PurchaseLine_articleId_idx" ON "PurchaseLine"("articleId");

-- CreateIndex
CREATE INDEX "PurchaseLine_variantId_idx" ON "PurchaseLine"("variantId");

-- CreateIndex
CREATE INDEX "PurchaseLine_jewelryId_idx" ON "PurchaseLine"("jewelryId");

-- CreateIndex
CREATE INDEX "PurchasePayment_purchaseId_idx" ON "PurchasePayment"("purchaseId");

-- CreateIndex
CREATE INDEX "PurchasePayment_supplierId_idx" ON "PurchasePayment"("supplierId");

-- CreateIndex
CREATE INDEX "PurchasePayment_jewelryId_idx" ON "PurchasePayment"("jewelryId");

-- CreateIndex
CREATE INDEX "PurchasePaymentComponent_paymentId_idx" ON "PurchasePaymentComponent"("paymentId");

-- CreateIndex
CREATE INDEX "PurchasePaymentComponent_jewelryId_idx" ON "PurchasePaymentComponent"("jewelryId");

-- CreateIndex
CREATE INDEX "PurchasePaymentComponent_metalId_idx" ON "PurchasePaymentComponent"("metalId");

-- AddForeignKey
ALTER TABLE "Purchase" ADD CONSTRAINT "Purchase_jewelryId_fkey" FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Purchase" ADD CONSTRAINT "Purchase_supplierId_fkey" FOREIGN KEY ("supplierId") REFERENCES "CommercialEntity"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Purchase" ADD CONSTRAINT "Purchase_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Purchase" ADD CONSTRAINT "Purchase_confirmedById_fkey" FOREIGN KEY ("confirmedById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Purchase" ADD CONSTRAINT "Purchase_cancelledById_fkey" FOREIGN KEY ("cancelledById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PurchaseLine" ADD CONSTRAINT "PurchaseLine_purchaseId_fkey" FOREIGN KEY ("purchaseId") REFERENCES "Purchase"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PurchaseLine" ADD CONSTRAINT "PurchaseLine_articleId_fkey" FOREIGN KEY ("articleId") REFERENCES "Article"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PurchaseLine" ADD CONSTRAINT "PurchaseLine_variantId_fkey" FOREIGN KEY ("variantId") REFERENCES "ArticleVariant"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PurchasePayment" ADD CONSTRAINT "PurchasePayment_jewelryId_fkey" FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PurchasePayment" ADD CONSTRAINT "PurchasePayment_purchaseId_fkey" FOREIGN KEY ("purchaseId") REFERENCES "Purchase"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PurchasePayment" ADD CONSTRAINT "PurchasePayment_supplierId_fkey" FOREIGN KEY ("supplierId") REFERENCES "CommercialEntity"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PurchasePayment" ADD CONSTRAINT "PurchasePayment_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PurchasePaymentComponent" ADD CONSTRAINT "PurchasePaymentComponent_paymentId_fkey" FOREIGN KEY ("paymentId") REFERENCES "PurchasePayment"("id") ON DELETE CASCADE ON UPDATE CASCADE;
