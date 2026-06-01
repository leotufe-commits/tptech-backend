-- Etapa Tax — Snapshot fiscal por documento (POLICY §Tax.6)
--
-- Agrega `Sale.documentFiscalSnapshot Json?` para persistir el scaling
-- aplicado al `taxAmount` cuando hay descuentos de cabecera (canal, cupón,
-- global). Nullable: ventas históricas no se tocan.
--
-- Backward compatibility: ventas previas a la regla §Tax quedan con el
-- snapshot en null. El `Sale.taxAmount` ya persistido es el válido para
-- esas ventas (regla histórica: era la suma de lineTaxAmount sin scaling).
-- Lecturas nuevas chequean si el snapshot está presente para mostrar el
-- detalle del scaling; si está null, asumen scaling no aplicado.

ALTER TABLE "Sale"
  ADD COLUMN "documentFiscalSnapshot" JSONB;
