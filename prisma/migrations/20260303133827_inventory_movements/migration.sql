/*
  Warnings:

  - You are about to drop the `InventoryItem` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `Movement` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `MovementLine` table. If the table is not empty, all the data it contains will be lost.

*/
-- CreateEnum
CREATE TYPE "InventoryMovementKind" AS ENUM ('IN', 'OUT', 'TRANSFER', 'ADJUST');

-- DropForeignKey
ALTER TABLE "InventoryItem" DROP CONSTRAINT "InventoryItem_jewelryId_fkey";

-- DropForeignKey
ALTER TABLE "Movement" DROP CONSTRAINT "Movement_createdById_fkey";

-- DropForeignKey
ALTER TABLE "Movement" DROP CONSTRAINT "Movement_fromWarehouseId_fkey";

-- DropForeignKey
ALTER TABLE "Movement" DROP CONSTRAINT "Movement_jewelryId_fkey";

-- DropForeignKey
ALTER TABLE "Movement" DROP CONSTRAINT "Movement_toWarehouseId_fkey";

-- DropForeignKey
ALTER TABLE "MovementLine" DROP CONSTRAINT "MovementLine_inventoryItemId_fkey";

-- DropForeignKey
ALTER TABLE "MovementLine" DROP CONSTRAINT "MovementLine_metalVariantId_fkey";

-- DropForeignKey
ALTER TABLE "MovementLine" DROP CONSTRAINT "MovementLine_movementId_fkey";

-- DropTable
DROP TABLE "InventoryItem";

-- DropTable
DROP TABLE "Movement";

-- DropTable
DROP TABLE "MovementLine";

-- DropEnum
DROP TYPE "MovementType";

-- CreateTable
CREATE TABLE "InventoryMovement" (
    "id" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "kind" "InventoryMovementKind" NOT NULL,
    "code" TEXT NOT NULL DEFAULT '',
    "note" TEXT NOT NULL DEFAULT '',
    "effectiveAt" TIMESTAMP(3) NOT NULL,
    "warehouseId" TEXT,
    "fromWarehouseId" TEXT,
    "toWarehouseId" TEXT,
    "createdById" TEXT,
    "deletedAt" TIMESTAMP(3),
    "voidedAt" TIMESTAMP(3),
    "voidedNote" TEXT NOT NULL DEFAULT '',
    "voidedById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "InventoryMovement_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "InventoryMovementLine" (
    "id" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "movementId" TEXT NOT NULL,
    "variantId" TEXT NOT NULL,
    "grams" DECIMAL(18,6) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "InventoryMovementLine_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "InventoryMovement_jewelryId_createdAt_idx" ON "InventoryMovement"("jewelryId", "createdAt");

-- CreateIndex
CREATE INDEX "InventoryMovement_jewelryId_effectiveAt_idx" ON "InventoryMovement"("jewelryId", "effectiveAt");

-- CreateIndex
CREATE INDEX "InventoryMovement_jewelryId_kind_idx" ON "InventoryMovement"("jewelryId", "kind");

-- CreateIndex
CREATE INDEX "InventoryMovement_warehouseId_idx" ON "InventoryMovement"("warehouseId");

-- CreateIndex
CREATE INDEX "InventoryMovement_fromWarehouseId_idx" ON "InventoryMovement"("fromWarehouseId");

-- CreateIndex
CREATE INDEX "InventoryMovement_toWarehouseId_idx" ON "InventoryMovement"("toWarehouseId");

-- CreateIndex
CREATE INDEX "InventoryMovement_deletedAt_idx" ON "InventoryMovement"("deletedAt");

-- CreateIndex
CREATE INDEX "InventoryMovementLine_jewelryId_createdAt_idx" ON "InventoryMovementLine"("jewelryId", "createdAt");

-- CreateIndex
CREATE INDEX "InventoryMovementLine_movementId_idx" ON "InventoryMovementLine"("movementId");

-- CreateIndex
CREATE INDEX "InventoryMovementLine_variantId_idx" ON "InventoryMovementLine"("variantId");

-- AddForeignKey
ALTER TABLE "InventoryMovement" ADD CONSTRAINT "InventoryMovement_warehouseId_fkey" FOREIGN KEY ("warehouseId") REFERENCES "Warehouse"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "InventoryMovement" ADD CONSTRAINT "InventoryMovement_fromWarehouseId_fkey" FOREIGN KEY ("fromWarehouseId") REFERENCES "Warehouse"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "InventoryMovement" ADD CONSTRAINT "InventoryMovement_toWarehouseId_fkey" FOREIGN KEY ("toWarehouseId") REFERENCES "Warehouse"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "InventoryMovement" ADD CONSTRAINT "InventoryMovement_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "InventoryMovement" ADD CONSTRAINT "InventoryMovement_voidedById_fkey" FOREIGN KEY ("voidedById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "InventoryMovement" ADD CONSTRAINT "InventoryMovement_jewelryId_fkey" FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "InventoryMovementLine" ADD CONSTRAINT "InventoryMovementLine_jewelryId_fkey" FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "InventoryMovementLine" ADD CONSTRAINT "InventoryMovementLine_movementId_fkey" FOREIGN KEY ("movementId") REFERENCES "InventoryMovement"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "InventoryMovementLine" ADD CONSTRAINT "InventoryMovementLine_variantId_fkey" FOREIGN KEY ("variantId") REFERENCES "MetalVariant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
