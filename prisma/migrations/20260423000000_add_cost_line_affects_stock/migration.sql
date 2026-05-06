-- AlterTable: ArticleCostLine — agrega flag affectsStock para componentes que descuentan stock al vender
ALTER TABLE "ArticleCostLine" ADD COLUMN IF NOT EXISTS "affectsStock" BOOLEAN NOT NULL DEFAULT false;

-- AlterTable: Sale — agrega referencia al movimiento de componentes generado al confirmar
ALTER TABLE "Sale" ADD COLUMN IF NOT EXISTS "componentMovementId" TEXT;

-- UniqueIndex: Sale.componentMovementId
CREATE UNIQUE INDEX IF NOT EXISTS "Sale_componentMovementId_key" ON "Sale"("componentMovementId");

-- ForeignKey: Sale.componentMovementId → ArticleMovement.id
ALTER TABLE "Sale" ADD CONSTRAINT "Sale_componentMovementId_fkey"
  FOREIGN KEY ("componentMovementId") REFERENCES "ArticleMovement"("id")
  ON DELETE SET NULL ON UPDATE CASCADE;
