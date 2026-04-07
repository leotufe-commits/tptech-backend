-- AddColumn: isStackable a Promotion y QuantityDiscount
-- Valor por defecto: true → compatibilidad total con registros existentes

ALTER TABLE "Promotion" ADD COLUMN "isStackable" BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE "QuantityDiscount" ADD COLUMN "isStackable" BOOLEAN NOT NULL DEFAULT true;
