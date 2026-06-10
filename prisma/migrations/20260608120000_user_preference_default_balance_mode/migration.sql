-- AlterTable
-- Preferencia de usuario para el "Tipo de saldo" por defecto en Factura de
-- ventas. Nivel de la jerarquía R11.4 entre cliente y lista de precios.
-- Valores esperados (validados en la capa de servicio): 'UNIFIED' | 'BREAKDOWN'.
-- NULL = sin preferencia (delega a lista/tenant/fallback).
ALTER TABLE "UserPreference" ADD COLUMN "defaultBalanceMode" TEXT;
