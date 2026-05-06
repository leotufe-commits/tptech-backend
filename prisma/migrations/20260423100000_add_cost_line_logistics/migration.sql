-- Agrega valor LOGISTICS al enum CostLineType para soportar costos de envío
-- a nivel de línea de costo. El motor procesa estas líneas igual que PRODUCT/SERVICE
-- (suman al hechuraTotal para márgenes).
--
-- Variantes esperadas (manejadas en frontend al crear la línea):
--   - envío fijo:    qty = 1, unitValue = monto fijo
--   - envío por peso: qty = peso (gr/kg), unitValue = $/unidad de peso
--   - envío gratis:  qty = 1, unitValue = 0
--
-- Si la línea aplica impuestos o no se controla con manualTaxIds del artículo,
-- igual que el resto de los componentes.

ALTER TYPE "CostLineType" ADD VALUE 'LOGISTICS';
