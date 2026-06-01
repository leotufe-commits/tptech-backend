-- Balance Mode (Fase 2) — schema seguro, sin recalcular saldos históricos.
--   · CurrentAccountMovement.balanceMode default UNIFIED para registros existentes.
--   · sourceDocumentType/Id agregados como NULL — no se backfillean (R11.7
--     "Ver origen" funcional sólo en movimientos NUEVOS post-fase-2).
--   · AccountMovementMetalEntry tabla nueva vacía — movimientos históricos
--     siguen sin metales (R11.8).
-- Ver `docs/balance-mode-architecture.md` Fase 2 y POLICY.md §11.

-- CreateEnum
CREATE TYPE "BalanceMode" AS ENUM ('UNIFIED', 'BREAKDOWN');

-- AlterTable
ALTER TABLE "CurrentAccountMovement"
    ADD COLUMN "balanceMode" "BalanceMode" NOT NULL DEFAULT 'UNIFIED',
    ADD COLUMN "sourceDocumentType" TEXT,
    ADD COLUMN "sourceDocumentId" TEXT;

-- CreateTable
CREATE TABLE "AccountMovementMetalEntry" (
    "id" TEXT NOT NULL,
    "movementId" TEXT NOT NULL,
    "jewelryId" TEXT NOT NULL,
    "metalParentId" TEXT,
    "metalParentName" TEXT NOT NULL,
    "gramsOriginal" DECIMAL(14,6) NOT NULL,
    "purity" DECIMAL(10,6),
    "gramsPure" DECIMAL(14,6) NOT NULL,
    "sourceLineId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AccountMovementMetalEntry_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "CurrentAccountMovement_sourceDocumentType_sourceDocumentId_idx" ON "CurrentAccountMovement"("sourceDocumentType", "sourceDocumentId");

-- CreateIndex
CREATE INDEX "AccountMovementMetalEntry_movementId_idx" ON "AccountMovementMetalEntry"("movementId");

-- CreateIndex
CREATE INDEX "AccountMovementMetalEntry_jewelryId_idx" ON "AccountMovementMetalEntry"("jewelryId");

-- CreateIndex
CREATE INDEX "AccountMovementMetalEntry_metalParentId_idx" ON "AccountMovementMetalEntry"("metalParentId");

-- CreateIndex
CREATE INDEX "AccountMovementMetalEntry_sourceLineId_idx" ON "AccountMovementMetalEntry"("sourceLineId");

-- CreateIndex
CREATE INDEX "AccountMovementMetalEntry_jewelryId_metalParentId_idx" ON "AccountMovementMetalEntry"("jewelryId", "metalParentId");

-- AddForeignKey
ALTER TABLE "AccountMovementMetalEntry" ADD CONSTRAINT "AccountMovementMetalEntry_movementId_fkey" FOREIGN KEY ("movementId") REFERENCES "CurrentAccountMovement"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AccountMovementMetalEntry" ADD CONSTRAINT "AccountMovementMetalEntry_jewelryId_fkey" FOREIGN KEY ("jewelryId") REFERENCES "Jewelry"("id") ON DELETE CASCADE ON UPDATE CASCADE;
