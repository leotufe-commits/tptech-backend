-- Vendedor por defecto del cliente/proveedor.
-- Nullable: las entidades existentes mantienen su comportamiento.
-- Cuando está poblado, en Factura de Venta tiene prioridad sobre el vendedor
-- favorito del sistema (ver sales.service.ts).
ALTER TABLE "CommercialEntity" ADD COLUMN "sellerId" TEXT;

ALTER TABLE "CommercialEntity"
  ADD CONSTRAINT "CommercialEntity_sellerId_fkey"
  FOREIGN KEY ("sellerId") REFERENCES "Seller"("id")
  ON DELETE SET NULL ON UPDATE CASCADE;

CREATE INDEX "CommercialEntity_sellerId_idx" ON "CommercialEntity"("sellerId");
