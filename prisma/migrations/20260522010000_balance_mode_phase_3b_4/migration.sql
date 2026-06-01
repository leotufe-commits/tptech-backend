-- Balance Mode (Fase 3B.4) — schema bump de configuración por documento /
-- cliente / lista / tenant. SIN runtime aún: ni preview ni confirm leen estos
-- campos todavía (eso es 3B.5).
--
-- Reglas (POLICY.md §11):
--   · Jewelry.defaultBalanceMode NOT NULL DEFAULT 'UNIFIED' — última red de
--     la prioridad R11.4. Sin backfill: el default cubre filas existentes.
--   · CommercialEntity.balanceMode NULL (sin default) — null = hereda
--     siguiente nivel (PriceList → Tenant).
--   · PriceList.balanceMode NULL (sin default) — null = hereda Tenant.
--   · Sale.balanceModeOverride / balanceMode / balanceModeSource NULL —
--     balanceModeOverride = override manual del documento; balanceMode =
--     modo resuelto/congelado al confirmar (poblar en 3B.5);
--     balanceModeSource = auditoría del nivel ganador.
--   · Purchase: mismos 3 campos NULL.
--   · CrossSettlement.balanceMode NULL.
--   · Receipt.balanceMode NULL — receipts metálicos quedan para Fase 5.
--
-- El enum `BalanceMode` ya existe desde la migración Fase 2
-- (20260522000000_balance_mode_phase_2) — no se vuelve a crear.
--
-- NO se backfilea, NO se recalculan saldos históricos, NO se modifican filas
-- existentes (módulo el default de Jewelry.defaultBalanceMode que cubre
-- automáticamente las filas previas con UNIFIED).

-- AlterTable: Jewelry
ALTER TABLE "Jewelry"
    ADD COLUMN "defaultBalanceMode" "BalanceMode" NOT NULL DEFAULT 'UNIFIED';

-- AlterTable: CommercialEntity
ALTER TABLE "CommercialEntity"
    ADD COLUMN "balanceMode" "BalanceMode";

-- AlterTable: PriceList
ALTER TABLE "PriceList"
    ADD COLUMN "balanceMode" "BalanceMode";

-- AlterTable: Sale
ALTER TABLE "Sale"
    ADD COLUMN "balanceModeOverride" "BalanceMode",
    ADD COLUMN "balanceMode" "BalanceMode",
    ADD COLUMN "balanceModeSource" TEXT;

-- AlterTable: Purchase
ALTER TABLE "Purchase"
    ADD COLUMN "balanceModeOverride" "BalanceMode",
    ADD COLUMN "balanceMode" "BalanceMode",
    ADD COLUMN "balanceModeSource" TEXT;

-- AlterTable: CrossSettlement
ALTER TABLE "CrossSettlement"
    ADD COLUMN "balanceMode" "BalanceMode";

-- AlterTable: Receipt
ALTER TABLE "Receipt"
    ADD COLUMN "balanceMode" "BalanceMode";
