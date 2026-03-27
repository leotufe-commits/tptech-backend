-- AlterTable: agregar campos de costo y margen a SaleLine
-- Todos opcionales (null mientras la venta está en DRAFT; se rellenan al confirmar)
ALTER TABLE "SaleLine" ADD COLUMN IF NOT EXISTS "unitCost"      DECIMAL(14,4);
ALTER TABLE "SaleLine" ADD COLUMN IF NOT EXISTS "totalCost"     DECIMAL(14,2);
ALTER TABLE "SaleLine" ADD COLUMN IF NOT EXISTS "unitMargin"    DECIMAL(14,4);
ALTER TABLE "SaleLine" ADD COLUMN IF NOT EXISTS "totalMargin"   DECIMAL(14,2);
ALTER TABLE "SaleLine" ADD COLUMN IF NOT EXISTS "marginPercent" DECIMAL(10,4);
