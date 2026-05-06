# Política oficial de Pricing y Snapshots — TPTech

> **Estado**: Borrador para aprobación.
> **Alcance**: backend `pricing-engine`, frontend de pricing/ventas/comparador, hooks de confirmación de documentos.
> **Vinculante**: una vez aprobada, cualquier código que la viole es bug y debe rechazarse en review.

---

## 1. Política oficial de redondeo

**Principio**: el redondeo comercial se aplica **una sola vez** y vive **dentro del pricing-engine**.

### Reglas absolutas

- **R1.1** — Solo existe **un único punto de redondeo final** del documento: la capa 10 del orden oficial (ver §5). Toda otra capa trabaja con precisión completa (Decimal o número con suficientes decimales).
- **R1.2** — La PriceList **no aplica redondeo comercial** salvo que el tenant tenga `documentRoundingEnabled=false`. Configuraciones incompatibles deben rechazarse al guardar la lista.
- **R1.3** — `roundingTarget=METAL` y `roundingTarget=HECHURA` son **redondeos de display de composición**, no de precio. No deben afectar el `unitPrice` que entra a la capa de descuentos.
- **R1.4** — El frontend **no aplica redondeo a montos**. Solo formatea para mostrar (`toLocaleString`, `Intl.NumberFormat`). Está prohibido `Math.round(x*100)/100` sobre subtotales, descuentos, impuestos o totales en la capa de normalización o display.
- **R1.5** — Cualquier ajuste de redondeo debe quedar capturado en el snapshot como `roundingAdjustment` (delta entre total pre-redondeo y total final).

### Lo que NO se hace

- No redondear por línea **y** por documento.
- No redondear en lista **y** en documento.
- No redondear en frontend, ni siquiera "para evitar 0.001".

---

## 2. Política oficial de snapshots

**Principio**: un documento confirmado debe ser **reproducible byte-a-byte** sin acceso a datos vivos (artículos, listas, cotizaciones, impuestos).

### Reglas absolutas

- **R2.1** — Al confirmar un documento, el snapshot persistido debe contener **todos los inputs** que influyeron en el cálculo: precio base, lista aplicada, descuentos resueltos, canal, cupón, forma de pago, impuestos resueltos, envío, política de redondeo, **cotización de moneda usada**, y composición metal/hechura.
- **R2.2** — Los snapshots son **inmutables**. No existen endpoints de `update` ni de `delete` sobre snapshots. La única forma de neutralizar un documento confirmado es `VOIDED`.
- **R2.3** — El snapshot debe ser **autosuficiente**: dado el snapshot guardado, recalcular los totales debe dar el mismo resultado sin leer la base.
- **R2.4** — Cualquier campo derivable que el frontend hoy reconstruye (split de descuento de cliente, gramos puros de venta, etc.) debe estar en el snapshot como campo persistido, no derivado en el cliente.
- **R2.5** — Si el motor agrega una capa nueva (ej: nuevo tipo de descuento), el snapshot debe extenderse. Versionar con `snapshotVersion`.

### Datos mínimos obligatorios en snapshot (ver §8 para la lista completa)

Por línea: `unitPriceBase`, `priceSource`, `priceListId+mode`, `quantityDiscountAmount`, `promotionDiscountAmount`, `customerDiscountAmount`, `metalSale`, `hechuraSale`, `pureGramsSale`, `taxBreakdown[]`, `lineTotal`, `costOverrideContext`.

Por documento: `subtotal`, `channelAdjustmentAmount`, `couponAdjustmentAmount`, `paymentAdjustmentAmount`, `globalDiscountAmount`, `shippingAmount`, `taxAmount`, `roundingAdjustment`, `total`, `currencyId+currencyRate`, `roundingPolicy`.

---

## 3. Política oficial de overrides manuales

**Principio**: un override manual es una **decisión explícita del usuario** y debe respetarse hasta que el usuario lo revoque explícitamente.

### Reglas absolutas

- **R3.1** — Cada campo de la línea con override tiene un flag booleano dedicado: `manualOverrides.{quantity, price, discount, tax}`. Mientras el flag esté en `true`, el preview del backend **no pisa** el valor.
- **R3.2** — El flag se limpia **únicamente** cuando:
  - el usuario cambia `articleId` o `variantId` de la línea, o
  - el usuario invoca explícitamente "Restablecer línea", o
  - el usuario edita el campo y vuelve al valor automático.
- **R3.3** — `blur` o `focus` **no** disparan recálculo del campo overrideado. Tampoco un re-fetch periódico ni el debounce de otra columna.
- **R3.4** — Un override válido viaja al backend como input (`manualPriceOverride`, `manualDiscountOverride`, `taxOverride`). El backend lo respeta y marca `priceSource="MANUAL_OVERRIDE"` en el snapshot.
- **R3.5** — El backend **registra** el override en el snapshot pero **no lo recalcula**. Si el override es inconsistente (ej: precio negativo), responde con error explícito; nunca lo "corrige" en silencio.
- **R3.6** — Una línea manual sin artículo (`articleId=null`) es válida y debe convivir con líneas de artículo en el mismo documento sin romper agregaciones.

---

## 4. Política oficial del frontend (lector puro)

**Principio**: el frontend **muestra**; el backend **calcula**.

### Reglas absolutas

- **R4.1** — El frontend **no calcula** precios, descuentos, impuestos, márgenes, totales, subtotales, gramos puros, gramos con merma, ajustes de canal/cupón/pago, ni envío.
- **R4.2** — El frontend **puede**:
  - formatear valores (decimales, separadores, moneda) para display,
  - construir el payload del request con los inputs del usuario,
  - mantener los flags de override manual,
  - manejar UI optimista mostrando el snapshot anterior mientras llega el preview nuevo.
- **R4.3** — El frontend **no puede**:
  - aplicar `Math.round(x*100)/100` ni `toFixed()` a montos antes de devolverlos a otra capa,
  - reconstruir campos derivados aritméticamente (ej: `customerDiscount = lineDiscount - qty - promo`),
  - calcular subtotal/total como fallback cuando llega data parcial,
  - inferir composición metal/hechura desde costo,
  - calcular envío por peso ni por cantidad.
- **R4.4** — Si el backend no devolvió un campo, el frontend muestra "—" o estado de carga. **Nunca** lo calcula.
- **R4.5** — Los normalizadores (`normalizePricingPreviewResult` y similares) **transforman shape**, no valores. Si tienen aritmética sobre montos, están mal.

---

## 5. Orden oficial e inmutable del pricing-engine

**Principio**: el orden de capas es **único, lineal e inmutable**. Nadie puede saltearlo, paralelizarlo ni reordenarlo.

```
1.  Costo
2.  Lista de precios / precio manual
3.  Promoción
4.  Descuento por cantidad
5.  Descuento de cliente / categoría / canal-jerárquico
6.  Canal de venta (recargo/descuento de canal)
7.  Cupón
8.  Forma de pago (recargo/descuento)
9.  Impuestos
10. Envío
11. Redondeo final del documento
12. Snapshot
```

### Reglas absolutas

- **R5.1** — Las capas se ejecutan **una sola vez por cálculo**.
- **R5.2** — Nadie fuera del motor puede alterar el orden ni inyectar capas.
- **R5.3** — Cada capa recibe el resultado de la anterior y produce un resultado tipado. Las capas no leen estado externo arbitrario.
- **R5.4** — Si una capa no aplica (no hay cupón, no hay envío, etc.), pasa el valor sin tocarlo y registra `none` en el snapshot.
- **R5.5** — Cambiar el orden requiere: (a) actualizar este documento, (b) actualizar `pricing-engine/README.md`, (c) tests de paridad antes/después, (d) bump de `snapshotVersion`.

> Nota técnica: la implementación actual aplica `payment` después de `taxes` a nivel documento (capa 8 conceptual = capa post-impuesto en código). Esto está justificado y debe quedar documentado en el README del motor; **no se considera violación** del orden mientras el README lo refleje.

---

## 6. Reglas de paridad simulador / factura / comparador

**Principio**: para el **mismo input**, los tres flujos deben devolver el **mismo output**.

### Reglas absolutas

- **R6.1** — Los tres flujos pasan por las mismas funciones del motor. No hay "motor del simulador" ni "motor del comparador".
- **R6.2** — El shape de respuesta es idéntico (`PricingSnapshot`). Las diferencias entre simulador y factura (ej: factura tiene `documentNumber`) viven **fuera** del snapshot, en metadatos del wrapper.
- **R6.3** — El simulador acepta el flag `applyDocumentRounding`. El comparador siempre lo pasa en `true` cuando contrasta contra factura.
- **R6.4** — El comparador **no calcula deltas inferidos**. Solo lee dos snapshots y muestra los campos lado a lado. Si un campo difiere, es bug del backend o de los inputs, nunca del comparador.
- **R6.5** — Los tests de paridad (`simulator-vs-invoice-parity`, `endpoint-parity`, `preview-confirm-parity`) son **bloqueantes**: si fallan, no se puede mergear.
- **R6.6** — Las tres formas de agregar línea (TPCombo, agregar rápido, escaneo) construyen el mismo payload. El backend no distingue origen.

---

## 7. Qué puede y qué NO puede calcular el frontend

### Puede

| Operación | Ejemplo |
|---|---|
| Formatear montos | `1234.5 → "$ 1.234,50"` |
| Construir payload | `{ articleId, quantity, manualOverrides }` |
| Mantener UI state | flags de override, expandir/colapsar paneles |
| Mostrar snapshot anterior | mientras llega el preview nuevo (UI optimista) |
| Disparar preview | con debounce, abort de pedidos viejos |
| Sumar **cantidades de líneas** para mostrar "5 ítems" | conteo, no monto |

### NO puede

| Operación prohibida | Por qué |
|---|---|
| `Math.round(x*100)/100` sobre montos | Contamina la capa de redondeo del backend |
| `precio × cantidad` para mostrar total de línea | El backend ya lo emite como `lineTotal` |
| `lineDiscount − qtyDisc − promoDisc` | El backend debe emitir `customerDiscountAmount` |
| `appliedGrams × purity × (1 + merma%)` | El backend debe emitir `pureGramsBase` y `pureGramsSale` |
| `precio/kg × kg` para envío | El backend resuelve `shippingAmount` desde `{mode, value, weight}` |
| Calcular IVA desde rate × base | El backend emite `taxBreakdown[]` con monto resuelto |
| Inferir margen desde precio − costo | El backend emite `marginAmount` y `marginPercent` |

---

## 8. Datos persistibles obligatorios

**Principio**: el snapshot debe contener todo lo necesario para reproducir el cálculo histórico.

### Por línea

```
unitPriceBase
priceSource: PROMOTION | MANUAL_OVERRIDE | QUANTITY_DISCOUNT | PRICE_LIST | MANUAL_FALLBACK | NONE
appliedPriceListId, appliedPriceListMode
appliedPromotionId
appliedQuantityDiscountId
quantityDiscountAmount
promotionDiscountAmount
customerDiscountAmount       ← NUEVO obligatorio
lineDiscountAmount           ← suma de los 3 anteriores
metalCost, metalSale, metalGramsBase
hechuraCost, hechuraSale
pureGramsBase, pureGramsSale ← NUEVO obligatorio
metalHechuraBreakdownSource: METAL_HECHURA | PROPORTIONAL_COST
breakdownEstimated: bool
costOverrideContext: { gramsOverride, mermaPercentOverride, metalVariantIdOverride, hechuraOverrideAmount } ← NUEVO obligatorio
manualOverridesApplied: { quantity, price, discount, tax }
taxBreakdown[]: { taxId, rate, base, amount, overriddenByEntity }
lineTotal, lineTaxAmount
```

### Por documento

```
subtotal
channelId, channelAdjustmentAmount, channelMode
couponId, couponAdjustmentAmount, couponMode
paymentMethodId, paymentAdjustmentAmount
globalDiscountAmount, globalDiscountMode
shippingMode, shippingValue, shippingWeight, shippingAmount
taxAmount (agregado)
roundingPolicy: { source, applyOn, mode, direction }
roundingAdjustment              ← delta exacto aplicado
total
currencyId, currencyRate        ← NUEVO obligatorio
snapshotVersion                 ← NUEVO obligatorio
computedAt                      ← timestamp
```

### Por hook de confirmación

```
receiptId (si emite comprobante)
currentAccountMovementId (si afecta cuenta corriente)
articleMovementId (si afecta stock)
```

---

## 9. Reproducibilidad histórica

**Principio**: dado un documento confirmado en T0, abrirlo en T1 (con artículos, listas y cotizaciones cambiadas) debe mostrar **exactamente** los mismos valores que en T0.

### Reglas absolutas

- **R9.1** — La pantalla de detalle de un documento confirmado lee **solo** del snapshot. No consulta `Article`, `PriceList`, `MetalQuote` ni `TaxRate` actuales.
- **R9.2** — El reporte/impresión de un comprobante usa el snapshot. No recalcula.
- **R9.3** — Si la app necesita un dato que no está en el snapshot (ej: nombre del cliente actualizado), lo busca en la entidad viva, pero **no usa** ese dato para alterar montos.
- **R9.4** — Versionado: si `snapshotVersion < current`, la app puede leer pero no modificar (modo legacy).
- **R9.5** — Migraciones de schema **no** alteran datos de snapshots existentes. Solo agregan columnas nuevas con defaults nulos.
- **R9.6** — `currencyRate` persistida en el snapshot es la única tasa válida para reproducir totales. La cotización viva nunca contamina un documento histórico.

---

## 10. Reglas para futuras pantallas hermanas

**Principio**: cualquier pantalla nueva que muestre precios cae bajo esta política sin excepción.

### Checklist obligatorio antes de mergear una pantalla nueva

- [ ] Consume el endpoint del motor (`/api/articles/:id/pricing-preview`, `/api/sales/preview`, o uno nuevo que pase por las mismas funciones del engine).
- [ ] Usa el normalizador estándar (`normalizePricingPreviewResult` o equivalente). No define normalizador propio.
- [ ] No tiene aritmética sobre montos en su capa de display.
- [ ] Si introduce un nuevo flujo (ej: cotización, presupuesto, remito valorizado), ese flujo está cubierto por al menos un test de paridad contra simulador o factura.
- [ ] Si necesita un campo nuevo, lo agrega al snapshot del backend, no lo calcula localmente.
- [ ] Si requiere un override manual nuevo, sigue el patrón de `manualOverrides` (§3).
- [ ] Si es una vista de documento histórico, lee solo del snapshot (§9).

### Pantallas previstas a corto plazo (todas bajo esta política)

- Presupuestos
- Notas de pedido
- Remitos valorizados
- Facturas A/B/C electrónicas
- Notas de crédito/débito
- Cuenta corriente con valorización al cierre
- Liquidaciones cruzadas (`cross-settlements`) — ya cumple
- Dashboard de márgenes — ya cumple

---

## Vigencia y proceso de cambio

Esta política se actualiza solo con:

1. Aprobación explícita del owner del producto.
2. Bump de `snapshotVersion` si el cambio afecta persistencia.
3. Tests de paridad antes/después en el mismo PR.
4. Update simultáneo de `pricing-engine/README.md` y `CLAUDE.md`.

Cualquier código fusionado que la viole es bug y debe revertirse.
