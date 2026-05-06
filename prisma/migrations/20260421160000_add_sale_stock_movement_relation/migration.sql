-- AlterTable: agregar stockMovementId a Sale (FK → ArticleMovement)
ALTER TABLE "Sale" ADD COLUMN "stockMovementId" TEXT;

-- CreateIndex: unique para la relación 1-a-1
CREATE UNIQUE INDEX "Sale_stockMovementId_key" ON "Sale"("stockMovementId");

-- AddForeignKey
ALTER TABLE "Sale" ADD CONSTRAINT "Sale_stockMovementId_fkey"
  FOREIGN KEY ("stockMovementId") REFERENCES "ArticleMovement"("id")
  ON DELETE SET NULL ON UPDATE CASCADE;
