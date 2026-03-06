-- CreateEnum
CREATE TYPE "MovementType" AS ENUM ('IN', 'OUT', 'TRANSFER', 'ADJUST');

-- CreateTable
CREATE TABLE "InventoryItem" (
    "id" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "sku" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "notes" TEXT NOT NULL DEFAULT '',
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "deletedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "InventoryItem_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Movement" (
    "id" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "type" "MovementType" NOT NULL,
    "fromWarehouseId" TEXT,
    "toWarehouseId" TEXT,
    "reference" TEXT NOT NULL DEFAULT '',
    "notes" TEXT NOT NULL DEFAULT '',
    "createdById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "deletedAt" TIMESTAMP(3),

    CONSTRAINT "Movement_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "MovementLine" (
    "id" TEXT NOT NULL,
    "movementId" TEXT NOT NULL,
    "metalVariantId" TEXT,
    "inventoryItemId" TEXT,
    "grams" DECIMAL(18,6),
    "units" INTEGER,
    "metalName" TEXT NOT NULL DEFAULT '',
    "variantName" TEXT NOT NULL DEFAULT '',
    "itemSku" TEXT NOT NULL DEFAULT '',
    "itemName" TEXT NOT NULL DEFAULT '',

    CONSTRAINT "MovementLine_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "InventoryItem_jewelryId_idx" ON "InventoryItem"("jewelryId");

-- CreateIndex
CREATE INDEX "InventoryItem_jewelryId_isActive_idx" ON "InventoryItem"("jewelryId", "isActive");

-- CreateIndex
CREATE INDEX "InventoryItem_deletedAt_idx" ON "InventoryItem"("deletedAt");

-- CreateIndex
CREATE INDEX "InventoryItem_jewelryId_deletedAt_idx" ON "InventoryItem"("jewelryId", "deletedAt");

-- CreateIndex
CREATE UNIQUE INDEX "InventoryItem_jewelryId_sku_key" ON "InventoryItem"("jewelryId", "sku");

-- CreateIndex
CREATE INDEX "Movement_jewelryId_createdAt_idx" ON "Movement"("jewelryId", "createdAt");

-- CreateIndex
CREATE INDEX "Movement_fromWarehouseId_idx" ON "Movement"("fromWarehouseId");

-- CreateIndex
CREATE INDEX "Movement_toWarehouseId_idx" ON "Movement"("toWarehouseId");

-- CreateIndex
CREATE INDEX "Movement_createdById_idx" ON "Movement"("createdById");

-- CreateIndex
CREATE INDEX "Movement_deletedAt_idx" ON "Movement"("deletedAt");

-- CreateIndex
CREATE INDEX "MovementLine_movementId_idx" ON "MovementLine"("movementId");

-- CreateIndex
CREATE INDEX "MovementLine_metalVariantId_idx" ON "MovementLine"("metalVariantId");

-- CreateIndex
CREATE INDEX "MovementLine_inventoryItemId_idx" ON "MovementLine"("inventoryItemId");

-- AddForeignKey
ALTER TABLE "InventoryItem" ADD CONSTRAINT "InventoryItem_jewelryId_fkey" FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Movement" ADD CONSTRAINT "Movement_jewelryId_fkey" FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Movement" ADD CONSTRAINT "Movement_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Movement" ADD CONSTRAINT "Movement_fromWarehouseId_fkey" FOREIGN KEY ("fromWarehouseId") REFERENCES "Warehouse"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Movement" ADD CONSTRAINT "Movement_toWarehouseId_fkey" FOREIGN KEY ("toWarehouseId") REFERENCES "Warehouse"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MovementLine" ADD CONSTRAINT "MovementLine_movementId_fkey" FOREIGN KEY ("movementId") REFERENCES "Movement"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MovementLine" ADD CONSTRAINT "MovementLine_metalVariantId_fkey" FOREIGN KEY ("metalVariantId") REFERENCES "MetalVariant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MovementLine" ADD CONSTRAINT "MovementLine_inventoryItemId_fkey" FOREIGN KEY ("inventoryItemId") REFERENCES "InventoryItem"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
