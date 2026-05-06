# pricing-engine

**Única fuente de verdad para todo cálculo comercial de TPTech.**

Todo lo que implique dinero, porcentajes, márgenes, impuestos o redondeos tiene que pasar por este motor. Nada de aritmética comercial fuera de este directorio.

---

## 📜 Documento vinculante: `POLICY.md`

`./POLICY.md` define las **reglas oficiales** del sistema comercial de TPTech. Es vinculante: cualquier código que la viole es bug y debe rechazarse en review.

Cubre:

- Política oficial de **rounding**
- Política oficial de **snapshots**
- Política oficial de **overrides manuales**
- Política oficial del **frontend (lector puro)**
- **Orden oficial e inmutable** del pricing-engine
- Reglas de **paridad** simulador / factura / comparador
- **Reproducibilidad histórica** de documentos confirmados
- Datos persistibles obligatorios y reglas para futuras pantallas hermanas

Antes de modificar cualquier capa del motor, leer `POLICY.md`.

---

## Qué cubre el motor

| Dominio | Funciones principales | Archivo |
|---|---|---|
| Costo de artículo | `calculateCostFromLines`, `buildBatchCostContext`, `resolveVariantAwareWeight` | `pricing-engine.cost.ts` |
| Precio de venta | `resolveFinalSalePrice`, `evaluatePricingPolicy`, `buildPricingSnapshot`, `isPromotionValid` | `pricing-engine.sale.ts` |
| Impuestos | `computeLineTaxes` (venta), `computePurchaseTaxes` (compra), `applyTaxesFromMap` (batch) | `pricing-engine.sale.ts` |
| Lista de precios | `resolvePriceList`, `applyPriceList`, `applyRounding`, `isPriceListValidNow` | `pricing-engine.pricelist.ts` |
| Canal de venta | `applySalesChannelAdjustment` | `pricing-engine.channel.ts` |
| Cupón | `applyCouponAdjustment` | `pricing-engine.coupon.ts` |
| Medio de pago | `resolveCheckoutPrice` | `pricing-engine.payment.ts` |
| Moneda y conversión | `getBaseCurrencyId`, `convertMoney`, `normalizeToBaseCurrency` | `pricing-engine.currency.ts` |
| Desglose metal/hechura | `buildBalanceBreakdownFromPrice` | `pricing-engine.balance.ts` |

---

## Orden de capas obligatorio

Cualquier flujo comercial (venta, simulador, preview de artículo, comprobante futuro) debe aplicar las capas en este orden:

```
1. Costo          →  calculateCostFromLines
2. Precio base    →  resolvePriceList + applyPriceList  (o MANUAL_OVERRIDE / MANUAL_FALLBACK)
3. Descuento por cantidad
4. Promoción
5. Margen y alertas
6. Canal de venta →  applySalesChannelAdjustment
7. Cupón          →  applyCouponAdjustment
8. Medio de pago  →  resolveCheckoutPrice
9. Impuestos      →  computeLineTaxes
10. Redondeo final (si la lista lo difirió)
```

Nunca aplicar canal después de cupón, ni cupón después del pago. El motor asume ese orden y cualquier desvío produce divergencias silenciosas entre preview y confirmación.

---

## Whitelist — módulos autorizados a importar del motor

Solo estos módulos pueden hacer `import … from "…/pricing-engine.js"`:

- `src/modules/articles/` — preview y listado de precios
- `src/modules/sales/` — confirmación de venta (en preparación)
- `src/modules/purchases/` — compras (en preparación)
- `src/modules/cross-settlements/` — liquidaciones cruzadas
- `src/modules/dashboard/` — lectura de snapshots ya calculados
- `src/modules/article-groups/` — lectura de precios enriquecidos por item
- Módulos futuros de **comprobantes**, **pagos** y **cuenta corriente** — lectura de snapshots

Cualquier módulo fuera de esta lista que necesite un cálculo comercial debe:
1. Pedir a uno de los módulos autorizados que exponga el dato calculado, o
2. Ser agregado a esta whitelist con justificación.

**No importar archivos internos del motor** (`pricing-engine.sale.ts`, `pricing-engine.pricelist.ts`, etc.). Usar siempre el barrel `pricing-engine.ts`.

---

## Reglas por tipo de ítem vendible

### Artículo simple (sin variantes)

- `salePrice`, `costPrice`, `useManualSalePrice`, `mermaPercent` y `manualTaxIds` viven en `Article`.
- El motor resuelve precio y costo a partir del propio artículo.

### Artículo padre (con variantes)

- Mismos campos comerciales que el simple. Las variantes heredan.
- El motor resuelve el precio del padre y lo aplica a la variante pedida.

### Variante

- **No tiene campos de precio ni costo propios.** El único override permitido es `weightOverride` (gramos).
- El motor lee siempre del artículo padre; la variante solo influye vía `weightOverride` sobre el costo de metal.
- La validación `assertNoVariantPricingOverrides` en `articles.service.ts` rechaza payloads que intenten guardar `salePrice`, `costPrice`, `useManualSalePrice`, `mermaPercent`, etc. en una variante.

### Servicio (`articleType = SERVICE`)

- Pasa por el mismo pipeline comercial que un producto: lista de precios, promociones, cupón, canal, pago, impuestos.
- **No tiene stock, no tiene metal, no tiene merma, no tiene hechura.** Su composición de costo solo admite líneas `SERVICE` o `MANUAL`.
- La validación `assertServiceArticleComposition` en `articles.service.ts` rechaza `mermaPercent != 0`, líneas `HECHURA`, líneas `METAL` y líneas con `metalVariantId`.

### Grupo (`ArticleGroup`)

- **Es alcance / presentación / filtro**, no motor de cálculo.
- Puede usarse para decidir qué promoción o qué cupón aplica (scope), pero el precio final siempre sale del ítem vendible concreto (artículo o variante del grupo).
- Nunca tiene `salePrice`, `costPrice` ni lógica de redondeo propia.

### Combo comercial (`commercialMode = COMBO_COMMERCIAL`)

- Es un artículo `PRODUCT` con `stockMode = NO_STOCK` y `sellWithoutVariants = true`.
- El motor lo resuelve recursivamente sumando el costo de cada componente (`_comboContext`), con anti-ciclo y profundidad máxima 5.
- El ajuste `comboAdjustmentKind + comboAdjustmentValue` se aplica sobre el subtotal del combo antes del pipeline de precio estándar.
- El stock se descuenta de los componentes con `affectsStock = true`, nunca del combo mismo.
- Las validaciones anti-ciclo y de componentes viven en `src/lib/combo.utils.ts` (no en el motor) porque operan sobre estructura de datos, no sobre dinero.

---

## Lo que el motor **no** hace (por diseño)

- No escribe en base de datos fuera de leer catálogos (precios, impuestos, cotizaciones).
- No conoce vendedores, comisiones, descuentos post-venta ni comprobantes — eso se resuelve fuera usando el snapshot del motor como input.
- No decide si una venta se confirma: solo calcula el resultado y emite alertas + policy (`evaluatePricingPolicy`). El módulo de ventas decide qué hacer con esas alertas.
- No calcula stock. Stock vive en `src/lib/stock-engine.ts` y `ArticleMovement`.

---

## Cómo extenderlo sin romperlo

1. ¿Es un cálculo comercial nuevo? Agregalo dentro de este directorio, nunca fuera.
2. ¿Reusa capas existentes (lista, canal, cupón, pago)? Componerlas en orden; no re-implementar.
3. ¿Necesita persistir el resultado? Usar `buildPricingSnapshot` y guardar el snapshot completo — nunca valores sueltos que después puedan recalcularse distinto.
4. Agregar test unitario en `__tests__/` antes de mergear.
