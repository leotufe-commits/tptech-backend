-- CreateEnum
CREATE TYPE "EntityType" AS ENUM ('PERSON', 'COMPANY');

-- CreateEnum
CREATE TYPE "BalanceType" AS ENUM ('UNIFIED', 'BREAKDOWN');

-- CreateEnum
CREATE TYPE "EntitySourceType" AS ENUM ('MANUAL', 'IMPORT_CSV', 'MIGRATION', 'API');

-- CreateEnum
CREATE TYPE "EntityRole" AS ENUM ('CLIENT', 'SUPPLIER');

-- CreateEnum
CREATE TYPE "AddressType" AS ENUM ('BILLING', 'SHIPPING', 'FISCAL', 'COMMERCIAL', 'OTHER');

-- CreateEnum
CREATE TYPE "BalanceEntryType" AS ENUM ('INVOICE', 'PAYMENT', 'CREDIT_NOTE', 'DEBIT_NOTE', 'ADJUSTMENT');

-- CreateEnum
CREATE TYPE "CommercialRuleScope" AS ENUM ('GLOBAL', 'METAL', 'VARIANT', 'CATEGORY');

-- CreateEnum
CREATE TYPE "CommercialRuleType" AS ENUM ('DISCOUNT', 'BONUS', 'SURCHARGE');

-- CreateEnum
CREATE TYPE "CommercialValueType" AS ENUM ('PERCENTAGE', 'FIXED_AMOUNT');

-- CreateEnum
CREATE TYPE "CommercialApplyOn" AS ENUM ('TOTAL', 'METAL_PRICE', 'HECHURA', 'METAL_Y_HECHURA');

-- CreateEnum
CREATE TYPE "TaxOverrideMode" AS ENUM ('INHERIT', 'EXEMPT', 'CUSTOM_RATE');

-- CreateTable
CREATE TABLE "CommercialEntity" (
    "id" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "code" TEXT NOT NULL,
    "displayName" TEXT NOT NULL,
    "entityType" "EntityType" NOT NULL DEFAULT 'PERSON',
    "isClient" BOOLEAN NOT NULL DEFAULT false,
    "isSupplier" BOOLEAN NOT NULL DEFAULT false,
    "firstName" TEXT NOT NULL DEFAULT '',
    "lastName" TEXT NOT NULL DEFAULT '',
    "companyName" TEXT NOT NULL DEFAULT '',
    "tradeName" TEXT NOT NULL DEFAULT '',
    "email" TEXT NOT NULL DEFAULT '',
    "phone" TEXT NOT NULL DEFAULT '',
    "documentType" TEXT NOT NULL DEFAULT '',
    "documentNumber" TEXT NOT NULL DEFAULT '',
    "ivaCondition" TEXT NOT NULL DEFAULT '',
    "balanceType" "BalanceType" NOT NULL DEFAULT 'UNIFIED',
    "creditLimitClient" DECIMAL(14,2),
    "creditLimitSupplier" DECIMAL(14,2),
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "deletedAt" TIMESTAMP(3),
    "sourceType" "EntitySourceType" NOT NULL DEFAULT 'MANUAL',
    "mergedIntoEntityId" TEXT,
    "notes" TEXT NOT NULL DEFAULT '',
    "avatarUrl" TEXT NOT NULL DEFAULT '',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CommercialEntity_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EntityAddress" (
    "id" TEXT NOT NULL,
    "entityId" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "type" "AddressType" NOT NULL DEFAULT 'OTHER',
    "label" TEXT NOT NULL DEFAULT '',
    "street" TEXT NOT NULL DEFAULT '',
    "streetNumber" TEXT NOT NULL DEFAULT '',
    "floor" TEXT NOT NULL DEFAULT '',
    "apartment" TEXT NOT NULL DEFAULT '',
    "city" TEXT NOT NULL DEFAULT '',
    "province" TEXT NOT NULL DEFAULT '',
    "country" TEXT NOT NULL DEFAULT 'Argentina',
    "postalCode" TEXT NOT NULL DEFAULT '',
    "isDefault" BOOLEAN NOT NULL DEFAULT false,
    "deletedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EntityAddress_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EntityContact" (
    "id" TEXT NOT NULL,
    "entityId" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "firstName" TEXT NOT NULL DEFAULT '',
    "lastName" TEXT NOT NULL DEFAULT '',
    "position" TEXT NOT NULL DEFAULT '',
    "email" TEXT NOT NULL DEFAULT '',
    "phone" TEXT NOT NULL DEFAULT '',
    "whatsapp" TEXT NOT NULL DEFAULT '',
    "isPrimary" BOOLEAN NOT NULL DEFAULT false,
    "receivesDocuments" BOOLEAN NOT NULL DEFAULT false,
    "receivesPaymentsOrCollections" BOOLEAN NOT NULL DEFAULT false,
    "portalAccess" BOOLEAN NOT NULL DEFAULT false,
    "notes" TEXT NOT NULL DEFAULT '',
    "deletedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EntityContact_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EntityCommercialRule" (
    "id" TEXT NOT NULL,
    "entityId" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "scope" "CommercialRuleScope" NOT NULL DEFAULT 'GLOBAL',
    "metalId" TEXT,
    "variantId" TEXT,
    "categoryId" TEXT,
    "ruleType" "CommercialRuleType" NOT NULL DEFAULT 'DISCOUNT',
    "valueType" "CommercialValueType" NOT NULL DEFAULT 'PERCENTAGE',
    "value" DECIMAL(10,4) NOT NULL,
    "applyOn" "CommercialApplyOn" NOT NULL DEFAULT 'TOTAL',
    "minQuantity" DECIMAL(10,4),
    "validFrom" TIMESTAMP(3),
    "validTo" TIMESTAMP(3),
    "notes" TEXT NOT NULL DEFAULT '',
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "sortOrder" INTEGER NOT NULL DEFAULT 0,
    "deletedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EntityCommercialRule_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EntityTaxOverride" (
    "id" TEXT NOT NULL,
    "entityId" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "taxId" TEXT NOT NULL,
    "overrideMode" "TaxOverrideMode" NOT NULL DEFAULT 'INHERIT',
    "customRate" DECIMAL(10,4),
    "applyOn" "TaxApplyOn",
    "notes" TEXT NOT NULL DEFAULT '',
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EntityTaxOverride_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EntityBalanceEntry" (
    "id" TEXT NOT NULL,
    "entityId" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "role" "EntityRole" NOT NULL DEFAULT 'CLIENT',
    "entryType" "BalanceEntryType" NOT NULL DEFAULT 'INVOICE',
    "amount" DECIMAL(14,2) NOT NULL,
    "currency" TEXT NOT NULL DEFAULT 'ARS',
    "documentRef" TEXT NOT NULL DEFAULT '',
    "notes" TEXT NOT NULL DEFAULT '',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdBy" TEXT NOT NULL DEFAULT '',
    "voidedAt" TIMESTAMP(3),
    "voidedBy" TEXT,
    "voidReason" TEXT NOT NULL DEFAULT '',

    CONSTRAINT "EntityBalanceEntry_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EntityAttachment" (
    "id" TEXT NOT NULL,
    "entityId" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "filename" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "mimeType" TEXT NOT NULL DEFAULT '',
    "size" INTEGER NOT NULL DEFAULT 0,
    "label" TEXT NOT NULL DEFAULT '',
    "deletedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "uploadedBy" TEXT NOT NULL DEFAULT '',

    CONSTRAINT "EntityAttachment_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "CommercialEntity_jewelryId_idx" ON "CommercialEntity"("jewelryId");

-- CreateIndex
CREATE INDEX "CommercialEntity_jewelryId_isActive_idx" ON "CommercialEntity"("jewelryId", "isActive");

-- CreateIndex
CREATE INDEX "CommercialEntity_jewelryId_isClient_isActive_idx" ON "CommercialEntity"("jewelryId", "isClient", "isActive");

-- CreateIndex
CREATE INDEX "CommercialEntity_jewelryId_isSupplier_isActive_idx" ON "CommercialEntity"("jewelryId", "isSupplier", "isActive");

-- CreateIndex
CREATE INDEX "CommercialEntity_jewelryId_displayName_idx" ON "CommercialEntity"("jewelryId", "displayName");

-- CreateIndex
CREATE INDEX "CommercialEntity_jewelryId_documentNumber_idx" ON "CommercialEntity"("jewelryId", "documentNumber");

-- CreateIndex
CREATE INDEX "CommercialEntity_deletedAt_idx" ON "CommercialEntity"("deletedAt");

-- CreateIndex
CREATE UNIQUE INDEX "CommercialEntity_jewelryId_code_key" ON "CommercialEntity"("jewelryId", "code");

-- CreateIndex
CREATE INDEX "EntityAddress_entityId_idx" ON "EntityAddress"("entityId");

-- CreateIndex
CREATE INDEX "EntityAddress_jewelryId_idx" ON "EntityAddress"("jewelryId");

-- CreateIndex
CREATE INDEX "EntityAddress_deletedAt_idx" ON "EntityAddress"("deletedAt");

-- CreateIndex
CREATE INDEX "EntityContact_entityId_idx" ON "EntityContact"("entityId");

-- CreateIndex
CREATE INDEX "EntityContact_jewelryId_idx" ON "EntityContact"("jewelryId");

-- CreateIndex
CREATE INDEX "EntityContact_deletedAt_idx" ON "EntityContact"("deletedAt");

-- CreateIndex
CREATE INDEX "EntityCommercialRule_entityId_idx" ON "EntityCommercialRule"("entityId");

-- CreateIndex
CREATE INDEX "EntityCommercialRule_jewelryId_idx" ON "EntityCommercialRule"("jewelryId");

-- CreateIndex
CREATE INDEX "EntityCommercialRule_deletedAt_idx" ON "EntityCommercialRule"("deletedAt");

-- CreateIndex
CREATE INDEX "EntityTaxOverride_entityId_idx" ON "EntityTaxOverride"("entityId");

-- CreateIndex
CREATE INDEX "EntityTaxOverride_jewelryId_idx" ON "EntityTaxOverride"("jewelryId");

-- CreateIndex
CREATE UNIQUE INDEX "EntityTaxOverride_entityId_taxId_key" ON "EntityTaxOverride"("entityId", "taxId");

-- CreateIndex
CREATE INDEX "EntityBalanceEntry_entityId_idx" ON "EntityBalanceEntry"("entityId");

-- CreateIndex
CREATE INDEX "EntityBalanceEntry_jewelryId_idx" ON "EntityBalanceEntry"("jewelryId");

-- CreateIndex
CREATE INDEX "EntityBalanceEntry_entityId_role_idx" ON "EntityBalanceEntry"("entityId", "role");

-- CreateIndex
CREATE INDEX "EntityAttachment_entityId_idx" ON "EntityAttachment"("entityId");

-- CreateIndex
CREATE INDEX "EntityAttachment_jewelryId_idx" ON "EntityAttachment"("jewelryId");

-- CreateIndex
CREATE INDEX "EntityAttachment_deletedAt_idx" ON "EntityAttachment"("deletedAt");

-- AddForeignKey
ALTER TABLE "CommercialEntity" ADD CONSTRAINT "CommercialEntity_jewelryId_fkey" FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EntityAddress" ADD CONSTRAINT "EntityAddress_entityId_fkey" FOREIGN KEY ("entityId") REFERENCES "CommercialEntity"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EntityContact" ADD CONSTRAINT "EntityContact_entityId_fkey" FOREIGN KEY ("entityId") REFERENCES "CommercialEntity"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EntityCommercialRule" ADD CONSTRAINT "EntityCommercialRule_entityId_fkey" FOREIGN KEY ("entityId") REFERENCES "CommercialEntity"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EntityTaxOverride" ADD CONSTRAINT "EntityTaxOverride_entityId_fkey" FOREIGN KEY ("entityId") REFERENCES "CommercialEntity"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EntityBalanceEntry" ADD CONSTRAINT "EntityBalanceEntry_entityId_fkey" FOREIGN KEY ("entityId") REFERENCES "CommercialEntity"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EntityAttachment" ADD CONSTRAINT "EntityAttachment_entityId_fkey" FOREIGN KEY ("entityId") REFERENCES "CommercialEntity"("id") ON DELETE CASCADE ON UPDATE CASCADE;
