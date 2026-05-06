-- Agrega TOTAL_AFTER_PAYMENT al enum CommissionBase.
-- Comisión calculada sobre total ajustado por canal + cupón + forma de pago.
-- Al momento de confirmSale usa TOTAL_AFTER_DISCOUNTS como provisional;
-- se actualiza en addPayment (primer pago) con el factor real del medio de pago.

ALTER TYPE "CommissionBase" ADD VALUE IF NOT EXISTS 'TOTAL_AFTER_PAYMENT';
