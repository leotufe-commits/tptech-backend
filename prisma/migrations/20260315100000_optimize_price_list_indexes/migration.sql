-- Eliminar índices redundantes o menos específicos
DROP INDEX IF EXISTS "PriceList_jewelryId_idx";
DROP INDEX IF EXISTS "PriceList_jewelryId_isActive_idx";
DROP INDEX IF EXISTS "PriceList_jewelryId_isFavorite_idx";

-- Índices compuestos con deletedAt (cubre los filtros reales de las queries)
CREATE INDEX "PriceList_jewelryId_deletedAt_isActive_idx" ON "PriceList"("jewelryId", "deletedAt", "isActive");
CREATE INDEX "PriceList_jewelryId_deletedAt_isFavorite_idx" ON "PriceList"("jewelryId", "deletedAt", "isFavorite");

-- Índices para channelId y clientId (futuros filtros por scope)
CREATE INDEX "PriceList_channelId_idx" ON "PriceList"("channelId");
CREATE INDEX "PriceList_clientId_idx" ON "PriceList"("clientId");

-- Restricción única: código único por tenant
-- NOTA: si hay códigos duplicados en la DB, esta sentencia fallará.
-- En ese caso ejecutar primero: UPDATE "PriceList" SET code = id WHERE code IN (SELECT code FROM "PriceList" GROUP BY "jewelryId", code HAVING count(*) > 1);
ALTER TABLE "PriceList" ADD CONSTRAINT "PriceList_jewelryId_code_key" UNIQUE ("jewelryId", "code");
