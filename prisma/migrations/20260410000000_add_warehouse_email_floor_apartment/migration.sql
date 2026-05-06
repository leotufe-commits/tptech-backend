-- AlterTable: agrega los campos de contacto/dirección faltantes al modelo Warehouse
ALTER TABLE "Warehouse" ADD COLUMN "email"     TEXT NOT NULL DEFAULT '';
ALTER TABLE "Warehouse" ADD COLUMN "floor"     TEXT NOT NULL DEFAULT '';
ALTER TABLE "Warehouse" ADD COLUMN "apartment" TEXT NOT NULL DEFAULT '';
