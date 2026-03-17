-- Fix: Seller.userId unique constraint should only apply to non-deleted sellers.
-- A simple @unique blocks recreation after soft-delete.

-- 1. Limpiar datos existentes: liberar userId de vendedores eliminados
UPDATE "Seller" SET "userId" = NULL WHERE "deletedAt" IS NOT NULL AND "userId" IS NOT NULL;

-- 2. Reemplazar índice único simple por uno parcial (solo activos)
DROP INDEX IF EXISTS "Seller_userId_key";
CREATE UNIQUE INDEX "Seller_userId_key" ON "Seller"("userId") WHERE "deletedAt" IS NULL;
