-- Fix metal variant purity values for AU18K and AG950.
-- No schema change — uses existing purity + saleFactor fields.
-- Formula: precio = referenceValue × purity × saleFactor

-- ─────────────────────────────────────────────────────────
-- Oro 18 Kilates (AU18K)
-- Antes : purity=0.825  saleFactor=1.0   → efectiva 0.825
-- Después: purity=0.750  saleFactor=1.10  → efectiva 0.825 (misma)
-- Impacto en precios: NINGUNO. Solo cambia la descomposición
-- semántica (pureza base 18/24 + 10% ajuste operacional).
-- ─────────────────────────────────────────────────────────
UPDATE "MetalVariant"
SET purity = '0.7500', "saleFactor" = '1.100000'
WHERE sku = 'AU18K';

-- ─────────────────────────────────────────────────────────
-- Plata 950 (AG950)
-- Antes : purity=0.9500  saleFactor=1.0  → efectiva 0.950
-- Después: purity=1.0000  saleFactor=1.0  → efectiva 1.000
-- Impacto en precios: la PRÓXIMA cotización calculará al
-- 100% del valor de referencia (antes era 95%).
-- Las cotizaciones ya guardadas en MetalQuote NO se tocan.
-- ─────────────────────────────────────────────────────────
UPDATE "MetalVariant"
SET purity = '1.0000', "saleFactor" = '1.000000'
WHERE sku = 'AG950';
