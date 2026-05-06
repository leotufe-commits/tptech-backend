-- Agrega dos nuevos valores al enum CommissionBase:
-- TOTAL_AFTER_DISCOUNTS  → total de venta ajustado por canal + cupón, antes de impuestos
-- HECHURA_AFTER_DISCOUNTS → componente hechura ajustado por canal + cupón

ALTER TYPE "CommissionBase" ADD VALUE IF NOT EXISTS 'TOTAL_AFTER_DISCOUNTS';
ALTER TYPE "CommissionBase" ADD VALUE IF NOT EXISTS 'HECHURA_AFTER_DISCOUNTS';
