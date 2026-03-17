-- AlterTable: agregar campos de persona de contacto al modelo Seller
ALTER TABLE "Seller" ADD COLUMN "contactName"  TEXT NOT NULL DEFAULT '';
ALTER TABLE "Seller" ADD COLUMN "contactPhone" TEXT NOT NULL DEFAULT '';
ALTER TABLE "Seller" ADD COLUMN "contactEmail" TEXT NOT NULL DEFAULT '';
