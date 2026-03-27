-- CreateEnum
CREATE TYPE "ArticleType" AS ENUM ('PRODUCT', 'SERVICE', 'MATERIAL');

-- CreateEnum
CREATE TYPE "ArticleMovementKind" AS ENUM ('IN', 'OUT', 'TRANSFER', 'ADJUST', 'OPENING');

-- AlterTable
ALTER TABLE "Article" ADD COLUMN     "articleType" "ArticleType" NOT NULL DEFAULT 'PRODUCT';

-- AlterTable
ALTER TABLE "ArticleStock" ADD COLUMN     "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
ADD COLUMN     "reservedQty" DECIMAL(14,4) NOT NULL DEFAULT 0;

-- CreateTable
CREATE TABLE "ArticleMovement" (
    "id" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "kind" "ArticleMovementKind" NOT NULL,
    "code" TEXT NOT NULL DEFAULT '',
    "note" TEXT NOT NULL DEFAULT '',
    "effectiveAt" TIMESTAMP(3) NOT NULL,
    "warehouseId" TEXT,
    "fromWarehouseId" TEXT,
    "toWarehouseId" TEXT,
    "createdById" TEXT,
    "voidedAt" TIMESTAMP(3),
    "voidedNote" TEXT NOT NULL DEFAULT '',
    "voidedById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ArticleMovement_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ArticleMovementLine" (
    "id" TEXT NOT NULL,
    "movementId" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "articleId" TEXT NOT NULL,
    "variantId" TEXT,
    "quantity" DECIMAL(14,4) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ArticleMovementLine_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ArticleMovement_jewelryId_createdAt_idx" ON "ArticleMovement"("jewelryId", "createdAt");

-- CreateIndex
CREATE INDEX "ArticleMovement_jewelryId_effectiveAt_idx" ON "ArticleMovement"("jewelryId", "effectiveAt");

-- CreateIndex
CREATE INDEX "ArticleMovement_jewelryId_kind_idx" ON "ArticleMovement"("jewelryId", "kind");

-- CreateIndex
CREATE INDEX "ArticleMovement_warehouseId_idx" ON "ArticleMovement"("warehouseId");

-- CreateIndex
CREATE INDEX "ArticleMovement_fromWarehouseId_idx" ON "ArticleMovement"("fromWarehouseId");

-- CreateIndex
CREATE INDEX "ArticleMovement_toWarehouseId_idx" ON "ArticleMovement"("toWarehouseId");

-- CreateIndex
CREATE INDEX "ArticleMovement_jewelryId_voidedAt_idx" ON "ArticleMovement"("jewelryId", "voidedAt");

-- CreateIndex
CREATE INDEX "ArticleMovementLine_movementId_idx" ON "ArticleMovementLine"("movementId");

-- CreateIndex
CREATE INDEX "ArticleMovementLine_articleId_idx" ON "ArticleMovementLine"("articleId");

-- CreateIndex
CREATE INDEX "ArticleMovementLine_variantId_idx" ON "ArticleMovementLine"("variantId");

-- CreateIndex
CREATE INDEX "ArticleMovementLine_jewelryId_idx" ON "ArticleMovementLine"("jewelryId");

-- AddForeignKey
ALTER TABLE "ArticleMovement" ADD CONSTRAINT "ArticleMovement_jewelryId_fkey" FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ArticleMovement" ADD CONSTRAINT "ArticleMovement_warehouseId_fkey" FOREIGN KEY ("warehouseId") REFERENCES "Warehouse"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ArticleMovement" ADD CONSTRAINT "ArticleMovement_fromWarehouseId_fkey" FOREIGN KEY ("fromWarehouseId") REFERENCES "Warehouse"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ArticleMovement" ADD CONSTRAINT "ArticleMovement_toWarehouseId_fkey" FOREIGN KEY ("toWarehouseId") REFERENCES "Warehouse"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ArticleMovement" ADD CONSTRAINT "ArticleMovement_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ArticleMovement" ADD CONSTRAINT "ArticleMovement_voidedById_fkey" FOREIGN KEY ("voidedById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ArticleMovementLine" ADD CONSTRAINT "ArticleMovementLine_movementId_fkey" FOREIGN KEY ("movementId") REFERENCES "ArticleMovement"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ArticleMovementLine" ADD CONSTRAINT "ArticleMovementLine_articleId_fkey" FOREIGN KEY ("articleId") REFERENCES "Article"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ArticleMovementLine" ADD CONSTRAINT "ArticleMovementLine_variantId_fkey" FOREIGN KEY ("variantId") REFERENCES "ArticleVariant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
