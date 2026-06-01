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
- **R3.7** — **Override manual de impuesto pisa la exención del cliente.** La exención (`entityTaxExempt`) es un **default de hidratación**, no un candado fiscal. Cuando el operador ingresa un `taxOverride` explícito sobre una línea con cliente exento, su intención supera la herencia: el motor aplica el override y el snapshot registra `taxExemptByEntity=false` (decisión manual). El operador puede anular su override (`value=0` o limpiar el flag) y la línea vuelve al default exento.
  - **Precedencia**: `taxOverride` > `entityTaxExempt` > impuestos heredados del artículo/categoría.
  - **Aplica también con `manualPriceOverride` activo**: si el operador puso precio manual + override de impuesto sobre cliente exento, el motor aplica ambos overrides; ninguno se descarta.
  - **Tests que blindan la regla**: `pricing-engine/__tests__/tax-exempt-manual-override.test.ts` y `pricing-engine/__tests__/manual-price-bonif-tax-applyon.test.ts` (T43.3).
- **R3.8** — **`manualPriceOverride` viaja desde `pricingMeta.manualPrice`, NO desde `unitPrice` hidratado.** El frontend persiste la **intención exacta** del operador en `meta.manualPrice`; el `unitPrice` del draft se hidrata desde el response del backend tras cada preview y puede arrastrar micro-redondeos (conversión de moneda, `applyOn=PRICE` de la lista, etc.). Si el siguiente payload se construyera desde `unitPrice`, ese drift cambiaría la firma del preview y dispararía un nuevo fetch → **loop infinito**. Mismo patrón vale para `manualDiscountOverride` (← `meta.manualDiscount`) y `taxOverride` (← `meta.taxOverride`).
  - **Test que blinda la regla**: `tptech-frontend/src/lib/sales/__tests__/buildSalePreviewPayload.test.ts` describe `T43.5`.

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

## 11. Balance Mode — Saldo Unificado y Saldo Desglosado

**Principio**: TPTech opera con dos modelos canónicos de saldo. Cada documento (venta, compra, recibo, ajuste) se persiste con un `balanceMode` explícito y congelado al confirmar. Esto define **cómo se persiste, cómo se factura, cómo entra a cuenta corriente, cómo se cobra y cómo se imprime**.

### Definiciones

- **`UNIFIED`** — El documento se expresa en **una sola moneda activa**. Los componentes metal/hechura existen internamente para auditoría (snapshot), pero el saldo persistido en cuenta corriente es un único monto monetario. Default histórico y para tenants sin política explícita.
- **`BREAKDOWN`** — El documento se desglosa en **dos dimensiones canónicas**:
  - Una colección de saldos en **gramos puros por metal padre** (uno por cada metal del documento).
  - Un único **saldo monetario** consolidado en la moneda activa, que absorbe **todo lo que no es metal**.

### Reglas absolutas

- **R11.1** — **Metales = gramos puros por metal padre.** La unidad canónica de acumulación es `gramsPure = gramsOriginal × purity`. Se persisten ambos valores (`gramsOriginal` y `gramsPure`) más la `purity` snapshot, para reproducibilidad histórica.
- **R11.2** — **Saldo monetario = todo lo demás.** Incluye, sumando o restando según corresponda:
  - `+` hechuras, productos, servicios
  - `+` impuestos (ver R11.3)
  - `−` bonificaciones, cupones, descuentos automáticos y manuales
  - `+` recargos
  - `+` ajustes manuales, redondeos monetarios, envíos
  - `±` canal de venta, forma de pago, costos financieros
- **R11.3** — **El IVA y todo otro impuesto SIEMPRE caen en saldo monetario, sin excepción.** Aunque el motor calcule el impuesto sobre la base metal (`applyOn=METAL`), su naturaleza es monetaria. Justificación: la AFIP factura impuestos en dinero, no en gramos. `applyOn=METAL` sólo define la BASE de cálculo, no el destino del monto resultante.
- **R11.4** — **Prioridad de resolución del `balanceMode`** del documento, en orden:
  1. Override manual del documento (operador eligió explícitamente).
  2. Default del cliente/proveedor (`CommercialEntity.balanceMode`).
  3. Default de la lista de precios (`PriceList.balanceMode`).
  4. Default del tenant (`Jewelry.defaultBalanceMode`).
- **R11.5** — El `balanceMode` se congela en el snapshot al **confirmar** el documento. No puede cambiar después. Un documento confirmado en `UNIFIED` no se "transforma" a `BREAKDOWN` y viceversa — son persistencias distintas.
- **R11.6** — **Cuenta corriente persiste según el modo**:
  - `UNIFIED` → un movimiento monetario único (`monetaryAmount` en la moneda del documento, sin entradas metálicas).
  - `BREAKDOWN` → un movimiento con `monetaryAmount` + N entradas de `AccountMovementMetalEntry` (una por metal padre presente).
- **R11.7** — **Trazabilidad obligatoria.** Cada movimiento debe poder responder "¿de qué documento salí?": persiste `sourceDocumentType` (SALE | PURCHASE | RECEIPT | ADJUSTMENT) y `sourceDocumentId`. Cada `AccountMovementMetalEntry` adicionalmente persiste `sourceLineId` (FK a la línea origen). El frontend debe exponer "Ver origen" en cada movimiento.
- **R11.8** — **Saldos históricos quedan `UNIFIED`.** La migración no recalcula ni reprocesa movimientos pre-existentes. Movimientos viejos: `balanceMode=UNIFIED`, `metalEntries=[]`. Movimientos nuevos creados post-fase-2 pueden ser BREAKDOWN. Coexisten sin tocar el pasado.
- **R11.9** — **Snapshot version bump obligatorio.** La estructura del snapshot de documento confirmado debe incluir, a partir de `snapshotVersion=6`:
  - `balanceMode: "UNIFIED" | "BREAKDOWN"` (congelado).
  - `metals: [{ metalParentId, metalParentName, gramsOriginal, purity, gramsPure }]` (puede ser `[]` en UNIFIED).
  - `monetaryBalance: number` (en moneda del documento).
  - Trazabilidad: `sourceDocumentType`, `sourceDocumentId`.
  Snapshots v5 o anteriores se leen como UNIFIED implícito (back-compat).
- **R11.10** — **El motor (`pricing-engine`) sigue siendo single source of truth.** Frontend NUNCA decide el `balanceMode` ni calcula la distribución metal/no-metal — solo:
  - Lee el `balanceMode` del documento/preview.
  - Muestra el card "Composición del total" visible (BREAKDOWN) u oculto-on-demand (UNIFIED).
  - Renderiza los gramos y monto que el motor ya emitió.

### Tests obligatorios para R11

Cualquier cambio que toque `balanceMode` debe:

1. Cubrir paridad preview ↔ confirm en ambos modos.
2. Verificar que IVA siempre suma a `monetaryBalance` independiente de `applyOn`.
3. Verificar que `Σ metals[i].gramsPure` se mantiene estable bajo qty/precio manual/promos.
4. Verificar que movimientos históricos cargados en DB continúan saldando correctamente (back-compat).

### Documentación complementaria

Ver `docs/balance-mode-architecture.md` para:

- Diagrama de dominio.
- Shape detallado del snapshot v3 (técnico — el nombre conceptual "v6" alude al hito de POLICY, pero el `DOCUMENT_SNAPSHOT_VERSION` real es `3`).
- Migración por fases (1 a 3B.8).
- Decisiones de diseño (por qué tabla relacional vs JSON, por qué IVA es monetario, etc.).
- Notas de UX (`docs/balance-mode-ui-notes.md`) — preparación para Fase 4.

### R11 — Reglas adicionales de hardening (Fase 3B.8)

- **R11.11** — **Defensive on grams.** `gramsOriginal` y `gramsPure` deben ser números finitos y > 0 para persistir en `AccountMovementMetalEntry`. NaN, Infinity, negativos o ≤ 1e-9 → fila descartada por `buildAccountMovementMetalEntryRows`. El movimiento monetario sigue siendo válido aunque ninguna fila de metal se persista (caso edge: línea solo hechura en BREAKDOWN).
- **R11.12** — **Defensive on monetary.** `monetaryBalance.amount` y `monetaryBalance.amountBase` deben ser números finitos para que la persistencia BREAKDOWN proceda. `isValidBalanceBreakdownForPersistence` rechaza NaN/Infinity y aborta la tx con `BALANCE_BREAKDOWN_REQUIRED` (status 422). Históricos no afectados (la guarda corre sólo en escrituras nuevas).
- **R11.13** — **Dedupe defensiva por metal padre.** Si el breakdown traseara dos entradas con el mismo `metalParentId`, `buildAccountMovementMetalEntryRows` las consolida sumando gramos y recalculando pureza ponderada — preserva el invariante "1 fila por padre por movimiento" sin crear duplicados accidentales.
- **R11.14** — **`balanceType` legacy queda deprecado.** El campo `CommercialEntity.balanceType` (enum `BalanceType`) sigue presente para back-compat pero NO se debe leer en flujos nuevos. El resolver lee primero `CommercialEntity.balanceMode` (canónico) y solo cae a `balanceType` cuando el nuevo campo es null. Migración destructiva diferida a una sub-fase futura.
- **R11.15** — **Histórico inmutable.** Snapshots con `version < 3` se leen vía `readBalanceBreakdown` devolviendo `LEGACY_UNIFIED` (UNIFIED implícito desde `totals.total`). Bajo ningún concepto se recompone `metals[]` desde un snapshot legacy — esos documentos quedan UNIFIED por definición histórica.

---

## §Rounding — Modelo de redondeo oficial TPTech (consolidado)

> Cierre arquitectónico del sistema de redondeo. Sección oficial que
> consolida el pipeline (POLICY §R-Rounding-1 a §R-Rounding-8) antes de
> implementar `manualAdjustment`.

### §R-Rounding-1 — Pipeline canónico del rounding

TPTech redondea ÚNICAMENTE en dos puntos del pipeline. Cualquier otra
aplicación de rounding sobre montos del documento es un bug arquitectónico.

```
─── MOTOR (pricing-engine) ─────────────────────────────────────────────────
1.  Costo                                  [pricing-engine.cost.ts]
2.  Margen / lista / precio manual         [pricing-engine.pricelist.ts]
3-6. Descuentos de línea                   [pricing-engine.sale.ts]
7.  computeLineTaxes                       [pricing-engine.sale.ts]
─── (computeSaleDocumentTotals) ─────────────────────────────────────────────
8.  Canal de venta                         [pricing-engine.channel.ts]
9.  Cupón                                  [pricing-engine.coupon.ts]
10. Bonificación global doc                [document.ts]
★ 11. REDONDEO DE LISTA                     [applyRounding, capa 2/11]
12. taxableBase final                      [document.ts:755]
13. taxAmount (con scaling §Tax.4)         [document.ts:769]
14. Envío + Forma de pago                  [document.ts]
★ 15. REDONDEO DE COMPROBANTE (Etapa 1B)    [document.ts:920+]
─── (documentTotals emitido) ───────────────────────────────────────────────
16. engineTotal                            ← SSOT (Sale.engineTotal)
─── (post-motor — fuera del pricing-engine) ────────────────────────────────
17. AJUSTE MANUAL UNIFIED (Etapa A)         [manual-adjustment/buildSnapshot.ts]
18. finalTotal                             = engineTotal + manualAdjustment
```

**Invariantes**:
- `engineTotal = documentTotals.total` emitido por el motor INMEDIATAMENTE
  después del rounding de comprobante. SIEMPRE auditable.
- Sin ajuste manual (`manualAdjustment == null`): `Sale.total === Sale.engineTotal`.
- Con ajuste manual UNIFIED: `Sale.total = engineTotal + manualAdjustment.totals.monetaryAdjustment`.
- El ajuste manual SOLO ocurre POST-motor — no recalcula impuestos, no
  modifica costos, no toca redondeos automáticos. Es un override comercial
  humano sobre el cierre del comprobante.
- Etapa A (implementada): scope=UNIFIED. Aplica sobre el TOTAL UNIFICADO
  del comprobante. Un único monto humano global. No distingue metales /
  hechura.
- Etapa C (implementada — SOLO manual): scope=BREAKDOWN. Aplica sobre el
  SALDO DESGLOSADO del comprobante. Dominios DISJUNTOS:
    a) Cada metal padre en GRAMOS (`targetGrams` o `deltaGrams`).
    b) Bucket HECHURA / SALDO MONETARIO (`monetaryAmount`).

  Definición canónica del bucket "hechura / saldo monetario" en BREAKDOWN:
    todo lo que NO es metal padre — hechura física, productos, servicios,
    impuestos, envío, descuentos, cupones, canal de venta, forma de pago,
    redondeos monetarios y ajustes monetarios manuales.

  Principio "no mezclar" (obligatorio):
    · Ajustes en gramos viven SOLO en su metal padre — no contaminan
      hechura ni otros metales.
    · Ajustes monetarios viven SOLO en el bucket hechura/saldo — no
      contaminan gramos de ningún metal.

  ── Equivalencia monetaria de ajustes en metales padre (REGLA CRÍTICA) ─

  Todo ajuste sobre un metal padre en modo BREAKDOWN impacta también
  monetariamente el comprobante — EXACTAMENTE igual que el redondeo
  BREAKDOWN. La equivalencia es CONSOLIDACIÓN FINANCIERA, no reasignación
  de dominio.

  Ejemplo:
    · Oro fino calculado: 0,908 g.
    · Operador ajusta: 1,000 g.
    · Delta físico: +0,092 g (vive en el metal padre "oro-fino").
    · metalPricePerGram: 100.000 (cotización snapshot del balance).
    · monetaryEquivalent: 0,092 × 100.000 = 9.200 (consolidación
      financiera; vive en el snapshot del METAL, no en hechura).

  El sistema debe:
    1. Mantener el ajuste físico DENTRO del dominio METAL
       (`breakdown.metals[i].postGrams = 1`,
        `breakdown.metals[i].deltaGrams = +0,092`).
    2. Calcular el equivalente monetario:
       `breakdown.metals[i].monetaryEquivalent = deltaGrams × metalPricePerGram`.
    3. Impactar monetariamente:
       · `Sale.total`
       · `totals.totalMonetaryAdjustment`
       · `totals.metalMonetaryEquivalent` (Σ por metal)
       · displays financieros del frontend.

  Pero NUNCA:
    × Mover el valor a `breakdown.monetary.amount` (hechura).
    × Convertir el ajuste físico en "ajuste monetario de hechura".
    × Mezclar dominios en el motor de precios.
    × Sumar `monetaryAdjustment + metalMonetaryEquivalent` fuera de
      `totalMonetaryAdjustment`.

  El ajuste físico sigue perteneciendo al metal padre correspondiente
  para siempre — auditoría, cuenta corriente metálica futura, snapshots.

  ── Estructura final de BREAKDOWN — dos dominios PARALELOS ─────────────

  Dominio A — METAL (por metal padre):
    · `gramsPure` físicos (preGrams / postGrams / deltaGrams).
    · `metalPricePerGram` snapshot.
    · `monetaryEquivalent` = consolidación $ del delta físico.

  Dominio B — HECHURA / SALDO MONETARIO (bucket único):
    · todo lo no-metal-padre:
      hechura + productos + servicios + impuestos + descuentos +
      cupones + envíos + canal + forma de pago + redondeos monetarios +
      ajustes monetarios manuales.

  Consolidación final:
    `totalMonetaryAdjustment = monetaryAdjustment + metalMonetaryEquivalent`

  Los dominios NO se mezclan conceptualmente entre sí — solo se suman
  en este consolidado financiero que define `Sale.total`.

  Disponible SOLO cuando el documento opera en modo BREAKDOWN
  (`balanceMode === "BREAKDOWN"`). Si llega scope=BREAKDOWN con
  balanceMode=UNIFIED → 400.
- Etapa NO implementada: redondeo físico AUTOMÁTICO de gramos (ej.
  Oro 0,96 g → 1,00 g por política de lista/comprobante). Ver §R-Rounding-13.
- Contrato universal de totals del snapshot (dominios DISJUNTOS):
  - `totals.monetaryAdjustment` = ajuste monetario directo del BUCKET
    HECHURA / SALDO MONETARIO. UNIFIED → unified.amount (no hay separación);
    BREAKDOWN → breakdown.monetary.amount (solo hechura/saldo).
  - `totals.metalMonetaryEquivalent` = Σ equivalentes $ de los deltas
    FÍSICOS de gramos por metal padre. UNIFIED = 0.
  - `totals.totalMonetaryAdjustment` = consolidado financiero =
    monetaryAdjustment + metalMonetaryEquivalent. Es lo único que se
    suma a `engineTotal`.
  - Invariante: `Sale.total = max(0, Sale.engineTotal + totals.totalMonetaryAdjustment)`.
  - Sumar `monetaryAdjustment` con `metalMonetaryEquivalent` solo es
    legítimo en `totalMonetaryAdjustment`. Nunca usar la suma como
    ingrediente del motor de precios — los dominios siguen disjuntos.
- Cuenta corriente metálica (gap conocido): `AccountMovementMetalEntry` NO
  se persiste todavía en confirm. `Sale.total` sí refleja el delta $; el
  snapshot lleva todo el detalle (preGrams/postGrams/deltaGrams/
  metalPricePerGram) para reconstruir las entries cuando se implemente la
  etapa siguiente de CC metálica.

### §R-Rounding-2 — Separación de dominios

Existen **dos dominios disjuntos** de rounding. Cada uno tiene precisión,
estrategia y snapshot propios. **Prohibido cruzar dominios** (ej. redondear
gramos en pesos).

| Dominio | Unidad | Estado |
|---|---|---|
| **Monetary rounding** | Moneda (ARS / USD / EUR) | ✅ Implementado (lista + comprobante) |
| **Metal rounding** | Gramos físicos | ❌ No implementado — etapa futura dedicada |

> **Aclaración Etapa A (Ajuste Manual UNIFIED)**: el BREAKDOWN del redondeo
> de COMPROBANTE (capa 15) opera ÚNICAMENTE sobre dominios MONETARIOS —
> redondea el subtotal $ del metal padre y el subtotal $ de la hechura por
> separado, pero NO toca los gramos físicos. El redondeo físico de gramos
> (ej. `Oro 0,96 g → 1,00 g` con su contraparte monetaria) queda como
> etapa futura (§R-Rounding-13). Idem para el AJUSTE MANUAL: Etapa A solo
> soporta scope=UNIFIED (un monto global); BREAKDOWN del ajuste manual
> (gramos + hechura por separado) es etapa siguiente.

### §R-Rounding-3 — Distinción visual lista vs comprobante (UI)

El componente `ROUNDING_MONETARY` del `balanceBreakdown.monetaryBalance.components[]`
puede provenir de dos fuentes que el operador necesita distinguir:

| Origen del `roundingAdjustment` | Cómo se renderiza | Atributo |
|---|---|---|
| **Lista** (`documentRoundingApplied == null`) | "Redondeo de lista" + caption "Ya incluido en el subtotal" — estilo italic/muted | `data-tp-rounding-source="LIST"` |
| **Comprobante** (`documentRoundingApplied != null`) | "Redondeo del comprobante" + caption con scope (UNIFIED/BREAKDOWN/BOTH) | `data-tp-rounding-source="DOCUMENT"` |

Implementación: `MonetarySummary.RoundingRow` en
`tptech-frontend/src/components/sales/TotalDelComprobanteCard/parts/MonetarySummary.tsx`.

### §R-Rounding-4 — BOTH mode: orden oficial

Cuando `Jewelry.documentRoundingScope = BOTH`, el orden inmutable es:

```
1. BREAKDOWN (metal + hechura por separado)
   ↓
2. UNIFIED (sobre el total ya ajustado por BREAKDOWN)
```

**Guards**:
- Si la capa UNIFIED produce delta 0 después de BREAKDOWN → NO se reporta
  como capa adicional (guard anti-fantasma).
- Si scope = BREAKDOWN o BOTH pero no hay datos metal/hechura en las líneas
  → `fallback = "NO_BREAKDOWN_DATA"`. En BOTH, UNIFIED igual se aplica.

Tests: `pricing-engine/__tests__/document-totals.test.ts` (BREAKDOWN + BOTH).

### §R-Rounding-5 — Anti doble-rounding (defensa en profundidad)

La prevención de doble rounding vive ENTERAMENTE en el RUNTIME del pipeline.
La validación de creación/edición de PriceList NO depende de la configuración
vigente del redondeo financiero del tenant (decisión arquitectónica vigente —
ver comentario "Prevención de doble redondeo (DECISIÓN ARQUITECTÓNICA)" en
`price-lists.service.ts`).

Por qué se sacó del modal de listas: la lista de precios es una regla
COMERCIAL REUSABLE. Un tenant puede cambiar la política financiera mañana
sin que sus listas existentes queden bloqueadas (y viceversa). Acoplar las
dos configuraciones impedía operativas legítimas (lista METAL_HECHURA
desglosada + tenant con `documentRoundingScope=BREAKDOWN`, etc.).

Mecanismos del runtime que previenen el doble rounding:

1. **`suppressListDeferredRounding`** (`document-rounding.ts:154`): cuando
   la política del comprobante está activa, `loadDocumentRoundingConfig`
   emite el flag `true`. El motor (`pricing-engine.sale.ts:1620`) suprime
   el rounding diferido (`applyOn=NET|TOTAL`) de la lista — el documento
   queda como única autoridad.

2. **Capa 16 (PHYSICAL)** (`document-physical-rounding-apply.ts`): cuando
   `metalDomain=PHYSICAL`, `loadDocumentRoundingConfig` además fuerza
   `documentRoundingModeMetal=NONE` en la entrada del motor — para evitar
   doble redondeo entre la capa 15.metal monetaria y la capa 16 física.

3. **Tests `double-rounding-trap.test.ts`**: validan que listas con
   cualquier config se pueden crear/editar; que `loadDocumentRoundingConfig`
   sigue emitiendo `suppressListDeferredRounding=true` cuando aplica; que
   crear/editar listas no toca `Jewelry.documentRounding*`.

### §R-Rounding-6 — `Sale.engineTotal` (auditoría pre-ajuste manual)

`Sale.engineTotal` (Decimal nullable, agregado en migración
`20260527170000_sale_engine_total`) snapshot del `documentTotals.total`
emitido por el motor INMEDIATAMENTE después de la capa 15 del pipeline.

Reglas:
- **Hoy** (sin manualAdjustment implementado): `Sale.total === Sale.engineTotal`.
- **Futuro**: `Sale.total = engineTotal + manualAdjustment.totals.monetaryAdjustment`.
- Filas históricas (pre-migración): `engineTotal = NULL` → fallback a `Sale.total`.
- Persistido en `confirmSale` (`sales.service.ts`).

Test: `preview-confirm-parity.test.ts` valida que `Sale.update.data.engineTotal === documentTotals.total`.

### §R-Rounding-7 — Invariante visual: Σ visible === hero

Lo que el operador ve al cierre del desglose ("Total final" al pie del
collapsible "Detalle financiero") DEBE coincidir EXACTAMENTE con el hero
del card. Sin drift, sin centavos perdidos.

Implementación: `TotalDelComprobanteCard` lee `totalDocument` del backend y
lo formatea con `formatByType(value, "MONEY")` tanto en el hero como en el
footer. Mismo número, mismo helper → mismo string.

Test: `TotalDelComprobanteCard.test.tsx` — describe "POLICY §R-Rounding-7"
con 10 casos parametrizados (UNIFIED/BREAKDOWN/BOTH, con/sin IVA,
descuentos, envío, payment, rounding lista, rounding comprobante, decimales,
total cero).

### §R-Rounding-8 — Multi-moneda (estado actual, oficial)

**El motor aplica rounding SIEMPRE en la moneda BASE del tenant**, no en la
moneda de display del documento. Razones:

- El motor calcula en BASE (regla raíz CLAUDE.md).
- `pricing-currency-display.ts` convierte el resultado (incluyendo deltas
  de rounding) a la moneda DISPLAY mediante `× rate`.
- El delta convertido a DISPLAY **puede ser fraccional** cuando el rate
  no es entero — comportamiento esperado, no bug.

**Comportamiento por tenant**:
- Tenants mono-moneda (caso típico): sin efectos.
- Tenants multi-moneda activa: el rounding "centena" en ARS puede no
  resultar en "centena" en USD/EUR tras la conversión.

**Decisión arquitectónica**: aceptable como estado actual. Si en el futuro
se requiere rounding nativo en DISPLAY, requiere reorganizar el pipeline
(rounding después de la conversión) — etapa dedicada, no bloquea
`manualAdjustment`.

### §R-Rounding-9 — Frontend: passthrough estricto

El frontend **NO** aplica matemática de rounding. Reglas obligatorias:

- Cero `Math.round` / `Math.ceil` / `Math.floor` sobre montos del backend.
- Cero `toFixed` / `toLocaleString` / `Intl.NumberFormat` ad-hoc.
- El hero del `TotalDelComprobanteCard` lee `documentTotals.total` directo.
- El componente `ROUNDING_MONETARY` se renderiza con `c.amount` exacto del
  `balanceBreakdown.monetaryBalance.components[]`.
- `formatByType(value, "MONEY")` es el único formateador autorizado
  (centralizado, config-aware del tenant).

Guards estáticos activos: `factura-format.guard.test.ts` +
`no-frontend-document-math.guard.test.ts`.

### §R-Rounding-10 — Snapshots persistidos (mapa)

| Snapshot | Dominio | Persistido en |
|---|---|---|
| `Receipt.pricingSnapshot.totals` | Cálculo completo del Receipt | `Receipt` |
| `SaleLine.pricingSnapshot` | Línea con rounding lista absorbido | `SaleLine` |
| `Sale.documentRoundingSnapshot` | Rounding doc Etapa 1B (scope + capas) | `Sale` |
| `Sale.documentFiscalSnapshot` | Tax scaling (§Tax.4) | `Sale` |
| `Sale.engineTotal` (§R-Rounding-6) | Total motor pre-ajuste manual | `Sale` |
| `Sale.manualAdjustmentSnapshot` (Etapas A + C) | Ajuste humano UNIFIED o BREAKDOWN final | `Sale` |
| `Sale.manualAdjustmentInput` (Etapas A + C) | Intención DRAFT del operador (consumida al confirmar y limpiada) | `Sale` |
| (futuro) `Sale.metalRoundingSnapshot` | Rounding gramos (si se implementa) | `Sale` |

Cada snapshot tiene shape inmutable propio. No se mezclan dominios.

### §R-Rounding-12 — Dominios oficiales: comercial vs financiero

> **Cierre conceptual del modelo de rounding monetario.** Define oficialmente
> por qué TPTech tiene DOS sistemas de rounding monetario distintos y por qué
> **no se deben unificar**.

#### Los dos dominios

| Dominio | Configurado en | Cuándo se aplica | Sobre qué actúa | Naming oficial |
|---|---|---|---|---|
| **Comercial** | `PriceList.roundingMode/Direction/ApplyOn` | **ANTES** de impuestos | Precio de venta unitario / lineTotal | **"Redondeo comercial"** |
| **Financiero** | `Jewelry.documentRoundingScope/Mode/Direction` (+ hechura/metal) | **DESPUÉS** de impuestos | Total final del comprobante a cobrar | **"Redondeo financiero"** |

Históricamente la UI los llamaba a ambos "Redondeo" sin contexto, generando
confusión operativa real (caso reportado: "Total 473.473,97 + Redondeo 26,03"
donde el operador asumía que faltaba aplicar el redondeo).

#### Por qué representan dominios distintos

| Aspecto | Comercial (Lista) | Financiero (Comprobante) |
|---|---|---|
| Audiencia conceptual | Vendedor / publicador / catálogo / ecommerce | Caja / cliente / cierre fiscal |
| Función comercial | Precios "psicológicos", retail, publicación, listas mayoristas con precios redondos | Cobro práctico (sin centavos imposibles), cierre de caja, conformidad fiscal |
| Momento del cálculo | Capa 2/11 del pipeline (precio comercial) | Capa 15 del pipeline (total final post-todo) |
| Impacto sobre IVA | Cambia base imponible (porque cambia el precio gravable) | NO cambia base imponible (post-impuestos) |
| Efecto sobre el operador | Define cómo se publica/lista | Define cuánto cobra realmente el cliente |
| Si se desactivan ambos | `lineTotal` queda con la precisión natural del cálculo (centavos) | El cliente paga el total exacto del motor (con centavos) |

#### Naming oficial (alineación visual y documental)

A partir de esta sección, toda la UI y documentación de TPTech usa los
nombres **oficiales**:

| Lugar | Antes | Ahora (oficial) |
|---|---|---|
| Lista de precios → bloque rounding | "Redondeo" | **"Redondeo comercial"** + caption "Se aplica sobre el precio comercial antes de impuestos" |
| Política de precios → bloque rounding | "Redondeo por comprobante" | **"Redondeo financiero"** + caption "Se aplica sobre el total final luego de impuestos" |
| `TotalDelComprobanteCard.RoundingRow` | "Redondeo de lista" / "Redondeo del comprobante" | **"Redondeo comercial"** / **"Redondeo financiero"** |
| `describeRoundingScope` (helper del listado de listas) | "Redondeo: Línea" / "Redondeo: Comprobante" | "Redondeo comercial" / "Redondeo financiero" |
| Caption del componente ROUNDING_MONETARY en breakdown | "Ya incluido en el subtotal" | "Antes de impuestos · ya incluido en el subtotal" / "Después de impuestos · {scope}" |

El atributo técnico `data-tp-rounding-source` (LIST | DOCUMENT) sigue
existiendo para tests; el cambio es exclusivamente textual y semántico.

#### Por qué NO se unifican

La auditoría arquitectónica confirmó que ambos dominios son **válidos por
diseño** y representan necesidades comerciales distintas:

1. **Tenants que solo necesitan lista con precios redondos** (retail/mayorista
   sin caja física): no quieren ningún rounding al cobro, sus precios ya son
   "lindos" por construcción.
2. **Tenants que solo necesitan rounding de caja** (no manejan precios
   redondos en lista, pero al cobrar sí redondean a la centena para evitar
   monedas chicas): el motor calcula con precisión, el comprobante cierra
   redondo.
3. **Tenants que combinan ambos** (BOTH): precios publicados redondos +
   cobro redondeado a la centena. Las protecciones anti doble-rounding
   (§R-Rounding-5) garantizan que no haya conflicto.

Unificar los dos dominios sacrificaría flexibilidad legítima sin beneficio
real.

#### Frontend: distinción visual obligatoria

El componente ROUNDING_MONETARY del breakdown DEBE distinguir visualmente
ambos dominios para evitar la confusión histórica (§R-Rounding-3):

- **Comercial**: label "Redondeo comercial", caption "Antes de impuestos · ya
  incluido en el subtotal", estilo italic/muted, `data-tp-rounding-source="LIST"`.
- **Financiero**: label "Redondeo financiero", caption "Después de impuestos
  · {scope}", estilo detail tier, `data-tp-rounding-source="DOCUMENT"`.

#### Migración

Esta sección es **solo wording + documentación**. No requiere migración de
DB, no cambia el motor, no afecta snapshots ni paridad preview/confirm. Los
nombres internos (`roundingMode`, `documentRoundingScope`, etc.) y los enums
DB se mantienen — el cambio es exclusivamente en lo que el operador lee.

### §R-Rounding-11 — Lo que NO redondea TPTech

Para evitar ambigüedad, este es el listado explícito de cosas que NO se
redondean automáticamente:

- **Costo unitario**, **margen %**, **costo total**: cálculo numérico puro,
  precisión completa (Decimal).
- **Impuestos por línea** (`lineTaxAmount`): cálculo con precisión 6
  decimales internos, suma a 2 decimales en `taxAmount` del documento
  (§Tax.4 controla el scaling).
- **Gramos de metal** (`gramsOriginal`, `gramsPure`, `appliedGrams`): pasan
  del cálculo al snapshot sin redondeo. Etapa futura: §R-Rounding-13
  ("Metal Rounding Engine v2").
- **`taxableBase`**: pasa con la precisión que emite la fórmula, sin
  rounding extra.
- **Subtotal antes / después de descuentos línea**: precisión 2 decimales
  por suma de líneas, sin aplicar rounding adicional.

### §R-Rounding-13 — Etapa D: Redondeo automático físico de gramos (diseño oficial)

> **Estado**: DOCUMENTADA oficialmente. NO implementada todavía. Sección
> de diseño cerrada que sirve como contrato de referencia cuando se
> arranque la implementación. Cualquier desvío al implementar requiere
> actualizar primero esta sección.

#### Resumen funcional

En modo BREAKDOWN, además del redondeo monetario actual (capa 15), el
documento puede aplicar un **redondeo automático físico** sobre los gramos
de cada metal padre. Comportamiento análogo al **ajuste manual BREAKDOWN
de metales** (Etapa C), pero automatizado por política del tenant.

**Ejemplo canónico**:
- Oro fino calculado: 0,908 g.
- Política: `step=INTEGER`, `direction=NEAREST`.
- Resultado: 1,000 g. `deltaGrams = +0,092`.
- `monetaryEquivalent = 0,092 × metalPricePerGram` ⇒ impacta `Sale.total`
  vía `metalMonetaryEquivalent` del snapshot, **sin moverse a hechura**.

Etapa D es una capa nueva del pipeline (capa 16). Las reglas del paralelo
con el ajuste manual BREAKDOWN (§R-Rounding-1) rigen también acá:

- El ajuste físico vive en el metal padre. Su `monetaryEquivalent` es
  consolidación financiera — NUNCA reasignación al bucket hechura.
- Los dos dominios (metal en gramos + hechura monetaria) permanecen
  PARALELOS. Solo se suman en `totalRoundingAdjustment`.

#### Alcance (decisión de la pregunta 1)

**Etapa D arranca en redondeo FINANCIERO (a nivel comprobante)**. Los
gramos por metal padre se consolidan a nivel documento — un metal Oro que
aparece en 3 líneas debe redondearse contra `Σ gramsPure`, no por línea
individual.

El redondeo COMERCIAL físico (lista de precios) queda fuera del alcance
inicial. Razones:

- Requiere reabrir el pricing-engine y reescribir el `applyOn=NET|TOTAL`
  por línea con gramos como dominio. Cambio profundo y arriesgado.
- El financiero ya cubre el caso operativo principal ("Oro al gramo entero
  para cerrar la venta").
- Una vez estabilizado el financiero, evaluar con datos reales si el caso
  comercial es necesario (Etapa D' futura).

#### Momento del pipeline (decisión de la pregunta 2)

El redondeo físico ocurre **DESPUÉS de impuestos, ANTES de emitir
`engineTotal`** — nueva capa 16 entre el redondeo monetario del comprobante
(capa 15) y el ajuste manual (capa 17):

```
─── (computeSaleDocumentTotals) ─────────────────────────────────────────────
 ...
13. taxAmount (con scaling §Tax.4)
14. Envío + Forma de pago
★ 15. REDONDEO MONETARIO DEL COMPROBANTE (Etapa 1B — hechura siempre,
       metal $ solo si metalDomain="MONETARY")
★ 16. REDONDEO FÍSICO DE GRAMOS (Etapa D — solo si metalDomain="PHYSICAL")
─── (documentTotals emitido) ───────────────────────────────────────────────
17. engineTotal = total post capa 15 + capa 16
─── (post-motor) ───────────────────────────────────────────────────────────
18. AJUSTE MANUAL (Etapa A / Etapa C)
19. finalTotal
```

**Por qué no antes de impuestos**: requeriría recalcular impuestos sobre
el nuevo metal valuation. La regla canónica de Etapa D dice "no
recalcular impuestos". Si se ronde después, el delta monetario derivado
del redondeo físico entra como ajuste post-impositivo, exactamente como
hace hoy el redondeo monetario (capa 15) y el ajuste manual (capa 17).

**Por qué la capa 16 está dentro de `computeSaleDocumentTotals` y antes
de emitir `engineTotal`**: el redondeo físico es una decisión del MOTOR
(política del tenant, no intervención humana). `engineTotal` debe
representar el resultado completo del motor, incluyendo capa 16.
Auditoría queda en `documentRoundingSnapshot` (junto con capa 15), no
en `manualAdjustmentSnapshot`.

#### Cotización usada (decisión de la pregunta 3)

`metalPricePerGram` = **`balanceBreakdown.metals[i].quotePriceSnapshot`**.

Razones:
- Ya está consolidado por metal padre (no por línea — capa 16 redondea a
  nivel padre).
- Es snapshot — fue capturado al construir el `balanceBreakdown` y vive
  en `Sale.documentRoundingSnapshot.breakdown.metalPhysical.metals[].metalPricePerGram`
  para auditoría/reproducción.
- Etapa C (ajuste manual BREAKDOWN) ya lo usa exactamente igual ⇒ paridad
  arquitectónica y semántica.

**No usar cotización viva** (catálogo actual de metales) en confirm —
rompería la invariante "el resultado del preview se reproduce en el
confirm aunque el precio del metal haya cambiado".

#### Snapshot propuesto (decisión de la pregunta 4)

Extender `Sale.documentRoundingSnapshot` con un sub-bloque opcional
`breakdown.metalPhysical`. Shape:

```typescript
type DocumentRoundingSnapshot = {
  scope: "UNIFIED" | "BREAKDOWN" | "BOTH",

  // Capa 15 (monetario) — existente
  unified?:   { mode, direction, preRounding, postRounding, adjustment } | null,
  breakdown?: {
    /** Discriminador del dominio del metal en BREAKDOWN.
     *  "MONETARY" (default, back-compat): capa 15 redondea metal $.
     *  "PHYSICAL" (Etapa D): capa 15 NO toca metal $; capa 16 redondea gramos. */
    metalDomain: "MONETARY" | "PHYSICAL",

    /** Metal en $ — solo cuando metalDomain="MONETARY". Null si "PHYSICAL". */
    metal?:   { mode, direction, preRounding, postRounding, adjustment } | null,
    /** Hechura/saldo monetario en $ — SIEMPRE monetario (no tiene sentido
     *  físico). Persiste igual en ambos modos. */
    hechura?: { mode, direction, preRounding, postRounding, adjustment } | null,

    /** Capa 16 — solo cuando metalDomain="PHYSICAL" y hay datos suficientes. */
    metalPhysical?: {
      metals: Array<{
        metalParentId:      string | null,
        metalParentName:    string,
        preGrams:           number,
        postGrams:          number,
        deltaGrams:         number,
        metalPricePerGram:  number,   // snapshot del quotePriceSnapshot
        monetaryEquivalent: number,   // = deltaGrams × metalPricePerGram
        mode:               string,   // INTEGER / DECIMAL_1 / DECIMAL_2 / HALF / QUARTER
        direction:          "NEAREST" | "UP" | "DOWN",
        source:             "TENANT_POLICY",  // futuro: "PRICELIST"
      }>,
      metalMonetaryEquivalent: number,         // Σ metals[].monetaryEquivalent
      fallback?: "NO_METAL_PRICE" | "NO_BREAKDOWN_DATA" | "NO_METALS_TO_ROUND" | null,
    } | null,

    combinedAdjustment: number,
  } | null,

  /** TOTAL CONSOLIDADO de TODAS las capas de redondeo del documento.
   *  Contrato extendido para Etapa D: */
  totals?: {
    /** Σ de los deltas monetarios de capa 15 (hechura + metal $ legacy). */
    monetaryRoundingAdjustment: number,
    /** Σ metalPhysical.metals[].monetaryEquivalent (capa 16). 0 en MONETARY. */
    metalMonetaryEquivalent:    number,
    /** Suma final usada por el motor — único monto que mueve engineTotal. */
    totalRoundingAdjustment:    number,
  },

  // Legacy back-compat — preservado.
  totalAdjustment: number,
  // ...
}
```

**Contrato universal (paralelo al de manual adjustment)**:

```
engineTotal = motorTotalSinRedondeo + totals.totalRoundingAdjustment
Sale.total  = max(0, engineTotal + manualAdjustmentSnapshot.totals.totalMonetaryAdjustment)
```

`totals.totalRoundingAdjustment = monetaryRoundingAdjustment + metalMonetaryEquivalent`
es la suma legítima entre dominios — vive SOLO en este consolidado, nunca
como ingrediente del motor.

#### Relación con redondeo monetario existente (decisión de la pregunta 5)

**Discriminador `breakdown.metalDomain: "MONETARY" | "PHYSICAL"`**.
Default `"MONETARY"` (back-compat — todos los tenants existentes siguen
igual sin migración de datos).

- `metalDomain="MONETARY"` ⇒ capa 15.metal redondea metal $; capa 16 NO actúa.
- `metalDomain="PHYSICAL"` ⇒ capa 15.metal **SKIP**; capa 16 redondea gramos
  y emite `metalMonetaryEquivalent`.
- `metalDomain="PHYSICAL"` + fallback ⇒ capa 16 marca el fallback y NO
  redondea. Decisión: en fallback NO se cae automáticamente a capa 15.metal
  (eso sería inesperado para el operador que pidió PHYSICAL). La política
  se respeta como "no redondear nada del metal en ese caso, alertar".

Hechura siempre se redondea monetariamente en capa 15 (no hay sentido
físico para el bucket no-metal).

**Evitar doble redondeo**: el `metalDomain` es excluyente entre capa 15.metal
y capa 16. Test guard estático: si `metalDomain="PHYSICAL"`, el snapshot
no debe tener `breakdown.metal != null` (solo `metalPhysical`).

#### Fallback (decisión de la pregunta 6)

| Condición | Acción | Marca en snapshot |
|---|---|---|
| Sin gramos en el documento (todas las líneas no-metal) | Capa 16 ni se ejecuta | (no snapshot) |
| `quotePriceSnapshot = null` en algún metal | Ese metal NO se redondea. Otros metales sí, si tienen cotización | `fallback: "NO_METAL_PRICE"` |
| Sin metales en el documento | Capa 16 marca fallback y emite `metals: []` | `fallback: "NO_METALS_TO_ROUND"` |
| `balanceBreakdown.metals = []` o sin estructura | Igual que `NO_BREAKDOWN_DATA` | `fallback: "NO_BREAKDOWN_DATA"` |
| `metalDomain="PHYSICAL"` pero tenant no configuró modes | Capa 16 NO actúa | (sin snapshot, `metalPhysical: null`) |

**Regla**: el fallback NUNCA cae silenciosamente al redondeo monetario
de capa 15.metal. Si el tenant configuró PHYSICAL, esa intención se
respeta — los metales sin cotización quedan SIN redondear pero auditados.

#### Interacción con ajuste manual (decisión de la pregunta 7)

Orden inmutable:

```
1. Capa 15 — Redondeo monetario del comprobante (hechura siempre; metal $ si MONETARY).
2. Capa 16 — Redondeo físico de gramos (si PHYSICAL).
3. engineTotal = total post capas 15 + 16 — congelado.
4. Capa 17 — Ajuste manual UNIFIED o BREAKDOWN (opera sobre engineTotal).
5. finalTotal = engineTotal + manualAdjustmentSnapshot.totals.totalMonetaryAdjustment (clamp ≥ 0).
```

Cuando el manual BREAKDOWN ajusta un metal padre que la capa 16 YA redondeó:
- `manualAdjustmentInput.breakdown.metals[i].preGrams` (implícito, no lo
  envía el frontend) = `documentRoundingSnapshot.breakdown.metalPhysical.metals[i].postGrams`.
- El helper de manual adjustment consulta el `balanceBreakdown` para el
  preGrams — y ese breakdown **ya refleja los gramos POST-redondeo** porque
  capa 16 ocurrió antes. Cero cambios necesarios en Etapa C.
- Snapshots separados: `documentRoundingSnapshot` (automático) y
  `manualAdjustmentSnapshot` (humano). Auditoría completa.

Caso edge: el operador puede revertir el redondeo automático con un
ajuste manual opuesto (ej. capa 16 redondeó +0,092, el operador ajusta
-0,092). El resultado neto cero está auditado en los dos snapshots, no
se cancelan entre sí.

#### Cuenta corriente metálica (decisión de la pregunta 8)

`AccountMovementMetalEntry` queda **fuera del alcance Etapa D**. Pero la
auditoría queda diseñada para reconstruir entries cuando se implemente
la etapa siguiente. Las entries físicas por metal padre se podrán
reconstruir desde:

- `documentRoundingSnapshot.breakdown.metalPhysical.metals[i]` (delta del
  motor por redondeo).
- `manualAdjustmentSnapshot.breakdown.metals[i]` (delta humano).
- `Sale` ya tiene `id`, `confirmedAt`, `clientId`, `currencyId`.
- Cada entry tendría `source: "PHYSICAL_ROUNDING" | "MANUAL_ADJUST" | "INVOICE_LINES"`.

**Sin entries metálicas todavía**: `Sale.total` ya refleja el consolidado
monetario total ⇒ saldo monetario del cliente correcto. Lo que falta es
el tracking físico del metal por separado para el cliente que opera en
cuenta corriente metálica. Diseñar entries en la etapa siguiente; no
mezclar acá.

#### Tests obligatorios (decisión de la pregunta 9)

**Helper puro `roundDocumentMetalGrams`** (D1):
- Redondeo INTEGER NEAREST: `0,908 → 1,000`, delta `+0,092`, equivalente.
- Redondeo INTEGER UP: `0,1 → 1,0`.
- Redondeo INTEGER DOWN: `0,9 → 0,0`.
- Redondeo DECIMAL_1 NEAREST: `0,908 → 0,9`, delta `-0,008`.
- Redondeo HALF NEAREST: `0,76 → 1,00`; `0,74 → 0,50`.
- Múltiples metales (Oro + Plata): cada uno con su modo.
- `deltaGrams = 0` (preGrams ya redondeado): no emite entry para ese metal.
- Sin `metalPricePerGram` en un metal: marca `NO_METAL_PRICE`; no
  redondea ese metal pero sí los otros.
- Sin metales en el documento: marca `NO_METALS_TO_ROUND`.
- Determinismo: mismo input → mismo output (preview/confirm parity).

**Integración preview** (D3):
- Preview emite `documentRoundingSnapshot.breakdown.metalPhysical`.
- `engineTotal` incluye `totals.totalRoundingAdjustment` de capa 15 + 16.
- Cuando `metalDomain="PHYSICAL"`, `breakdown.metal` (monetario) es `null`.

**Integración confirm** (D4):
- Sale.documentRoundingSnapshot persistido inmutable.
- Sale.engineTotal refleja capa 15 + 16.
- Paridad preview ↔ confirm byte a byte (mismo `metalMonetaryEquivalent`).

**Multimoneda** (D5):
- Gramos (preGrams/postGrams/deltaGrams) NUNCA convertidos.
- `metalPricePerGram` y `monetaryEquivalent` convertidos base→display.
- `totals.{metalMonetaryEquivalent, monetaryRoundingAdjustment, totalRoundingAdjustment}` convertidos.

**Interacción con ajuste manual** (D3/D4):
- preGrams del manual = postGrams del redondeo físico (no preGrams
  originales) ⇒ test que valida que el `balanceBreakdown` que ve el helper
  manual refleja el resultado post capa 16.
- Snapshots permanecen en campos separados (sanity).

**Anti contaminación de hechura**:
- `metalDomain="PHYSICAL"`: snapshot tiene `breakdown.metal = null` y
  `breakdown.monetary.amount` (manual) NO incluye el `metalMonetaryEquivalent`.
- `totals.monetaryRoundingAdjustment` NO incluye el equivalente metal.

**Anti doble redondeo**:
- Cuando `metalDomain="PHYSICAL"`, capa 15 no opera sobre metal $.
- Suite específica que valida que no hay overlap entre `breakdown.metal`
  y `breakdown.metalPhysical` en el snapshot.

**Fallback**:
- `NO_METAL_PRICE`: ese metal queda en preGrams en el snapshot, otros
  sí redondean.
- `NO_METALS_TO_ROUND`: no falla, marca fallback.

#### Plan por etapas (decisión de la pregunta 10)

| Etapa | Alcance | Tests obligatorios | Riesgo |
|---|---|---|---|
| **D0** ✅ | POLICY.md §R-Rounding-13 + CLAUDE.md raíz § Etapa D (esta sección). Sign-off del usuario. | — | Bajo (docs only) |
| **D1** ✅ | Helper puro `roundDocumentMetalGrams(input)` en `lib/document-physical-rounding.ts`. Función pura, sin DB, determinística. | 38 tests verdes (modes, directions, fallbacks, empates, determinismo, no-mutación). | Bajo — código aislado |
| **D2** ✅ | Schema migration aditiva: `Jewelry.documentRoundingMetalDomain` (enum `DocumentRoundingMetalDomain`, default `MONETARY`) + `Jewelry.documentPhysicalRoundingConfig Json?`. Enums nuevos `PhysicalRoundingMode` y `PhysicalRoundingDirection`. Helper `lib/document-physical-rounding-config.ts` parsea el JSON al shape de D1 con degradación segura. **Runtime NO lo consume todavía** — los campos quedan listos para D3. | 17 tests del parser + smoke E2E ligero (default MONETARY, roundtrip JSON, rollback). | Bajo |
| **D3** ✅ | Integración como capa 16. `loadDocumentRoundingConfig` ahora también lee `metalDomain` + `physicalConfig`; cuando PHYSICAL, fuerza `metalCfg=NONE` en lo que pasa al motor (anti doble redondeo). Nuevo helper orquestador `lib/document-physical-rounding-apply.ts` invocado en `previewSale` y `confirmSale` después de `buildSaleBalanceBreakdown`: corre `roundDocumentMetalGrams`, muta `documentTotals.total`, escribe `documentRoundingApplied.breakdown.metalPhysical` + `metalDomain="PHYSICAL"`, agrega bloque universal `totals = { monetaryRoundingAdjustment, metalMonetaryEquivalent, totalRoundingAdjustment }`, y actualiza `balanceBreakdown.metals[i].gramsPure` para que el ajuste manual posterior (Etapa C) lea `preGrams = postGrams capa 16`. `convertSalesPreviewResponseInPlace` extendido para convertir `metalPricePerGram`, `monetaryEquivalent` y los 3 campos de `totals` (gramos invariantes). `pricing-engine.document.ts` **NO** se modificó. | 15 tests del orquestador cubriendo las 9 secciones del brief (A..I): MONETARY back-compat, PHYSICAL básico, DOWN, múltiples metales, anti doble redondeo, fallbacks (NO_METAL_PRICE / NO_CONFIG / NO_METALS_TO_ROUND), BOTH, interacción con ajuste manual, multimoneda. | Medio |
| **D4 (D5 ahora incluido en D3)** | confirm parity + persistencia ya están en D3. Pendiente: tests E2E integración real con `previewSale` / `confirmSale` (los 4 fallos de `preview-confirm-parity.test.ts` por mock incompleto de `taxScaling` son pre-existentes — no de D3). | Tests confirm + parity con mock completo. | Bajo |
| **D6** | UI Configuración → Política de Precios: switch UNIFIED/BREAKDOWN ya existe → agregar selector "Dominio metal: monetario / físico" + tabla "Modo por metal padre". UI en Total del comprobante: mostrar redondeo físico en `documentRoundingApplied` con caption "Redondeo automático de gramos". | Tests de render + format guard. | Medio — superficie UX |
| **D7** | PDF/mail: opcionalmente exponer el delta de redondeo físico por metal en el comprobante (ej. fila "Redondeo Oro: 0,908 → 1,000 g (+9.200)"). Decisión separada según necesidad fiscal. | Tests pdf-parity extendidos. | Medio |
| **D8** | Guards estáticos: validar que ningún consumer suma `metalMonetaryEquivalent` a `monetaryRoundingAdjustment` fuera de `totalRoundingAdjustment`. | Guard tests. | Bajo |
| **D9 (futuro, separado de D)** | `AccountMovementMetalEntry`: persistir entries físicas por metal padre. Usa los snapshots de D1-D4. Sesión dedicada. | — | Alto — toca cuenta corriente viva |

#### Riesgos identificados

- **Doble redondeo si `metalDomain` mal cableado**: blindar con guard
  test específico (capa 15.metal y capa 16 son mutuamente excluyentes).
- **Snapshot legacy en filas viejas**: campos nuevos son opcionales,
  migración aditiva. Lectores legacy ignoran `metalPhysical` y `totals`.
- **Cotización ausente**: `quotePriceSnapshot = null` es común en testing
  local sin metales reales — fallback debe ser robusto y testeado.
- **Confusión UI**: el operador puede mezclar conceptualmente el
  redondeo automático físico con el ajuste manual BREAKDOWN. Caption en
  el card debe ser explícito: "Redondeo automático del comprobante
  (TPTech)" vs "Ajuste manual (Vendedor ajustó)".
- **Tenants que ya usaban `metalDomain` implícitamente como MONETARY**:
  el default explícito MONETARY garantiza back-compat exacta. Cero
  riesgo de regresión para tenants existentes hasta que activen PHYSICAL.

#### Preguntas abiertas (requieren decisión del usuario antes de D1)

1. **Granularidad de configuración**: ¿`metalPhysicalModeByParent` es
   `{ [metalParentId]: { mode, direction } }` por metal padre, o un único
   modo global para todos los metales? Recomiendo por metal padre (Oro
   en INTEGER, Plata en HALF) — más útil en joyería real.
2. **Modos soportados**: ¿`INTEGER | DECIMAL_1 | DECIMAL_2 | HALF | QUARTER`?
   El último (`QUARTER`, al 0,25 más cercano) es típico para piedras y
   plata. Definir el enum oficial.
3. **¿La política vive en `Jewelry` o también en `PriceList`?**
   Recomiendo SOLO `Jewelry` para D, alineado con el redondeo financiero
   (Etapa 1B). `PriceList` queda como Etapa D' futura si hay demanda.
4. **PDF**: ¿el comprobante impreso debe mostrar el detalle del redondeo
   físico por metal, o solo el total? Decisión que afecta D7 — no
   bloquea D1-D6.
5. **¿La capa 16 corre dentro de `computeSaleDocumentTotals` o como
   sub-fase aparte?** Recomendado: dentro (mismo módulo que capa 15);
   evita exponer el orden interno al caller.

#### Cuándo empezar

D0 (esta sección) ya está cerrada. **D1 puede arrancar cuando se
confirmen las decisiones de las 5 preguntas abiertas**. El resto del plan
es ejecución directa con el diseño congelado.

---

### §R-Rounding-14 — Contrato canónico del modo DESGLOSADO (CRÍTICO ABSOLUTO)

> **DESGLOSADO = metal padre físico + hechura / saldo monetario.**

Este es el **contrato canónico** del sistema y APLICA POR IGUAL a los tres
mecanismos de redondeo/ajuste cuando operan en modo BREAKDOWN:

1. **Redondeo comercial** (origen: lista de precios).
2. **Redondeo financiero** (origen: configuración del comprobante / joyería).
3. **Ajuste manual** (origen: intervención del operador).

Los tres mecanismos deben respetar la MISMA separación de dominios. Cualquier
divergencia entre ellos es BUG arquitectónico.

#### 1. Dominio metal padre — SIEMPRE físico en gramos

Los metales padre se llaman por su denominación química **pura** (no por
variante / kilataje):

- Oro Fino
- Plata
- Platino
- (y cualquier metal padre futuro)

**No confundir** con las variantes de aleación (Oro 18 Kilates, Plata 925,
etc.) — esas son representaciones físicas del padre, no el padre mismo.

Todo redondeo o ajuste aplicado a un metal padre DEBE:

- ✅ modificar gramos físicos (`preGrams → postGrams`, `deltaGrams = postGrams − preGrams`),
- ✅ calcular **equivalente monetario** = `deltaGrams × metalPricePerGram` (snapshot del precio por gramo del balance),
- ✅ impactar el `Sale.total` vía ese equivalente monetario,
- ✅ quedar auditado en el snapshot persistido con el shape canónico
  `{ metalParentId, metalParentName, preGrams, postGrams, deltaGrams, metalPricePerGram, monetaryEquivalent, mode?, direction?, source?, fallback? }`.

Todo redondeo o ajuste aplicado a un metal padre NUNCA DEBE:

- ❌ moverse al bucket hechura,
- ❌ contaminar `monetaryAdjustment` / `monetary.amount`,
- ❌ mezclarse con el bucket monetario en ningún campo persistido.

**Ejemplo canónico**:

```
Oro Fino 0,908 g → 1,000 g
  preGrams           = 0,908
  postGrams          = 1,000
  deltaGrams         = +0,092
  metalPricePerGram  = 100.000  (snapshot del balance)
  monetaryEquivalent = 0,092 × 100.000 = 9.200

⇒ Sale.total += 9.200 (vía totalMonetaryAdjustment)
⇒ NO se mueve a hechura. NO suma a monetary.amount.
⇒ Queda persistido en breakdown.metals[i] del snapshot correspondiente.
```

#### 2. Dominio hechura / saldo monetario — SIEMPRE monetario

El bucket **monetario** incluye **todo lo que NO es metal padre**:

- hechura (sale subtotal del componente hechura),
- productos,
- servicios,
- impuestos (IVA, percepciones, fijos),
- descuentos (línea, manual, cliente),
- cupones,
- envíos,
- canal de venta,
- forma de pago (ajuste por checkout),
- redondeos monetarios,
- ajustes monetarios manuales.

Este bucket SIEMPRE se trata monetariamente. Tiene un único campo
`amount` (con signo) y NO se desglosa por sub-tipo a nivel de snapshot
del mecanismo BREAKDOWN — los sub-tipos viven en sus capas anteriores
del pipeline (capas 1–14).

Todo redondeo o ajuste aplicado al bucket monetario DEBE:

- ✅ modificar `amount` en pesos (sin pasar por gramos),
- ✅ impactar el `Sale.total` vía `totals.monetaryAdjustment`,
- ✅ quedar auditado como `{ amount, mode?, direction?, reason? }`.

#### 3. Consolidación financiera (único punto donde los dos dominios se suman)

Los dos dominios PERMANECEN PARALELOS en todos los campos del snapshot.
Solo se suman en un único campo agregado:

```
totals.totalMonetaryAdjustment
  = totals.monetaryAdjustment              (bucket monetario directo)
  + totals.metalMonetaryEquivalent         (Σ equivalentes monetarios de los Δgramos)
```

Esa suma es la que define el delta sobre `engineTotal` y por ende el
`Sale.total` final. **Fuera de ese campo agregado, los dos dominios
nunca se cruzan.**

#### 4. Aplicación a los tres mecanismos

| Mecanismo | Origen | Metal padre | Hechura / saldo monetario |
|---|---|---|---|
| **Comercial BREAKDOWN** | Lista de precios | Físico en gramos | Monetario |
| **Financiero BREAKDOWN** | `Jewelry.documentRoundingScope=BREAKDOWN` | Físico en gramos | Monetario |
| **Manual BREAKDOWN** | Operador (`scope=BREAKDOWN`) | Físico en gramos | Monetario |

Cualquier mecanismo que internamente redondee o ajuste el **subtotal $ del
metal directamente** (sin pasar por gramos × metalPricePerGram) **NO cumple
este contrato** y se considera lógica legacy. Ver §R-Rounding-14-legacy.

#### 5. Estado de cumplimiento al momento de definir esta regla

| Mecanismo | Estado canónico | Notas |
|---|---|---|
| **Manual BREAKDOWN** (Etapa C) | ✅ Cumple | `ManualAdjustmentSnapshotMetalEntry` lleva el shape canónico completo. |
| **Financiero BREAKDOWN — `metalDomain=PHYSICAL`** (Etapa D, capa 16) | ✅ Cumple | `applyDocumentPhysicalRounding` redondea gramos por padre y emite `monetaryEquivalent`. Hechura monetaria por capa 15.hechura. |
| **Financiero BREAKDOWN — `metalDomain=MONETARY`** (default histórico) | ⚠️ Legacy | Redondea subtotal $ del metal. Compat hacia atrás; **no es la regla funcional**. Plan: convertir el default a PHYSICAL en tenants nuevos. |
| **Comercial BREAKDOWN** (`PriceList.mode=METAL_HECHURA`, `pricing-engine.pricelist.ts:319-326`) | ⚠️ Legacy | Redondea subtotales $ del metal y de la hechura por línea. **No cumple la regla** — requiere migración a una capa "comercial PHYSICAL" análoga a la capa 16. |

#### §R-Rounding-14-legacy — Excepción explícita

Toda lógica que redondee directamente el subtotal monetario del metal
(`metalSale en pesos`) sin pasar por la fórmula `gramos × metalPricePerGram`
se reconoce como **compatibilidad histórica**, NO como el contrato
funcional canónico.

Reglas para esa lógica legacy:

- Permanece en producción para no romper a tenants existentes.
- No se extiende a mecanismos nuevos.
- En cualquier rediseño o nueva etapa, el contrato canónico (gramos físicos
  + equivalente monetario) es el destino obligatorio.
- Los tests deben dejar explícito qué es "legacy MONETARY metal" y qué es
  "canónico PHYSICAL metal" para que la diferencia no se confunda con un
  bug.

#### 6. Resumen visual del contrato (lectura rápida)

```
DESGLOSADO ⇒ dos dominios paralelos, jamás mezclados:

  ┌────────────────────────────────────────────────────────────┐
  │  A. METAL PADRE (por metal: Oro Fino, Plata, Platino, …)   │
  │  ───────────────────────────────────────────────────────   │
  │  · gramos físicos:        preGrams → postGrams (Δgramos)   │
  │  · metalPricePerGram:     snapshot del balance              │
  │  · monetaryEquivalent:    Δgramos × metalPricePerGram       │
  │    ↳ consolida en totals.metalMonetaryEquivalent            │
  │    ↳ NUNCA se mueve a hechura                               │
  └────────────────────────────────────────────────────────────┘

  ┌────────────────────────────────────────────────────────────┐
  │  B. HECHURA / SALDO MONETARIO (bucket único)               │
  │  ───────────────────────────────────────────────────────   │
  │  · amount $:  Σ todo lo que NO es metal padre               │
  │    (hechura + productos + servicios + impuestos + dtos     │
  │     + cupones + envíos + canal + pago + redondeos $        │
  │     + ajustes $ manuales)                                   │
  │    ↳ consolida en totals.monetaryAdjustment                 │
  └────────────────────────────────────────────────────────────┘

  ┌────────────────────────────────────────────────────────────┐
  │  C. CONSOLIDACIÓN FINANCIERA (único punto de cruce)        │
  │  ───────────────────────────────────────────────────────   │
  │  totals.totalMonetaryAdjustment                             │
  │    = totals.monetaryAdjustment                              │
  │    + totals.metalMonetaryEquivalent                         │
  │                                                             │
  │  Sale.total = engineTotal + totals.totalMonetaryAdjustment │
  └────────────────────────────────────────────────────────────┘
```

> **Objetivo funcional de TPTech**: `DESGLOSADO = metal físico + hechura monetaria`.
> Toda etapa nueva, cualquier mecanismo de redondeo/ajuste, frontend, backend,
> snapshot y reporte de auditoría deben respetar esta separación. Cualquier
> excepción solo se admite como compatibilidad histórica documentada.

---

### §R-Rounding-16 — Patrimonio comercial visual vs canónico interno (UX joyería)

> **Estado**: Decisión registrada el **2026-05-30**. Vigente en frontend; backend sin cambios. Excepción visual al contrato §R-Rounding-14, **no** una alternativa de cálculo del motor.

#### 1. Contexto del problema

El contrato canónico §R-Rounding-14 define el **bucket metal padre** como **físico puro** en gramos: `valuationMonetary = gramsPure × quotePriceSnapshot`. Esa fórmula es la única autorizada para la valuación interna del metal (cuenta corriente metálica futura, snapshots persistidos, auditoría).

Sin embargo, en la **operativa comercial de joyería** el operador no piensa en "gramos puros × cotización snapshot". Piensa en "lo que el cliente paga por el metal incorporado a la joya" — un valor que incluye **merma**, **margen comercial del metal** y **redondeo físico**. Ese valor corresponde a `metalCost` del cost-line (= `qty × purity × (1+merma) × unitValue`).

Mostrar `valuationMonetary` como "Patrimonio Metálico" en el card del operador deja una **diferencia inexplicada** (`metalCost − valuationMonetary`) que el motor emite como component `METAL_MARGIN` del `monetaryBalance`. Auditoría UX 2026-05-29 mostró que esa fila genera confusión: parece un cobro extra suelto.

#### 2. Decisión

El **frontend** del card "Total del comprobante" muestra como "Patrimonio Metálico":

- **Valor visual mostrado**: `metalCost` (suma agregada del documento = `documentTotals.metalCostSubtotal`).
- **Valor canónico interno**: `valuationMonetary` físico puro — sigue calculado por el motor, persistido en snapshots, y disponible para cuenta corriente metálica.

Identidad matemática preservada en pantalla:

```
Patrimonio Metálico mostrado    = Σ metalCost
Saldo Monetario mostrado        = totalDocument − Σ metalCost
Patrimonio + Saldo               = totalDocument                    ✅
Σ components visibles del detalle == Saldo Monetario                ✅
```

Como `metalCost` ya incluye `valuationMonetary + METAL_MARGIN`, el component `METAL_MARGIN` del detalle **se suprime visualmente** (filtro frontend exclusivamente — el backend sigue emitiéndolo).

#### 3. Reglas

- **El backend NO cambia.** Sigue emitiendo `valuationMonetary` (canónico), `metalCost`, `METAL_MARGIN`, todos los demás campos. La estructura del snapshot persistido es idéntica a antes — auditoría y reproducibilidad histórica intactas.
- **Solo el frontend re-interpreta** qué mostrar al operador:
  - "Patrimonio Metálico" visual = `Σ metalCost` (no `Σ valuationMonetary`).
  - "Saldo Monetario" visual = `totalDocument − Σ metalCost` (no `totalDocument − Σ valuationMonetary`).
  - El component `METAL_MARGIN` se filtra del render de `MonetarySummary` (filtro `c.type !== "METAL_MARGIN"`).
- **`valuationMonetary` sigue siendo la fuente de verdad** para:
  - Cuenta corriente metálica (cuando se implemente — POLICY §11).
  - `AccountMovementMetalEntry` (deuda en gramos físicos).
  - Auditoría histórica / drill-down del snapshot.
  - Cualquier reporte fiscal o regulatorio del metal físico.
- **Si el caller no provee `commercialMetalValueSum`** al card, el frontend degrada al modo canónico §R-Rounding-14: Patrimonio = `Σ valuationMonetary`, METAL_MARGIN visible. Eso preserva back-compat con consumers viejos.

#### 4. Verificación matemática

Para el caso real auditado (artículo "ANILLO SOLITARIO BRILLANTE", qty=1, Lista Desglosada, Oro 1.5 g, purity 0.75, merma 10%):

| Magnitud | Valor | Origen |
|---|---:|---|
| `valuationMonetary` (canónico interno) | $210.937,50 | `gramsPure × quotePriceSnapshot` |
| `metalCost` (comercial visual) | $309.375,00 | `qty × purity × (1+merma) × unitValue` |
| METAL_MARGIN (= `metalCost − valuationMonetary`) | $98.437,50 | absorbido en Patrimonio visual (no se renderiza) |
| Hechura | $142.500,00 | `hechuraSaleSubtotal` |
| IVA | $93.417,19 | `taxAmount` |
| Redondeo físico | −$7.031,25 | `monetaryEquivalent` del rounding |
| Total final | $538.260,94 | `documentTotals.total` |

```
Modo R-Rounding-16 (visual operador):
  Patrimonio Metálico:  ARS 309.375,00       ← Σ metalCost
+ Saldo Monetario:
    Hechura            142.500,00
    IVA                 93.417,19
    Redondeo            −7.031,25
    ────────────────  ───────────
    Σ Saldo            228.885,94            = totalDocument − Σ metalCost ✅
──────────────────────────────────────
  TOTAL                538.260,94            = Sale.total ✅

Cero líneas extra. Cero magia. METAL_MARGIN no visible (absorbido en Patrimonio).
```

#### 5. Trade-offs reconocidos

- **Divergencia visual vs canónico**: el operador ve un Patrimonio ($309.375) distinto al valuationMonetary canónico ($210.937,50). Si en el futuro hay pantalla de cuenta corriente metálica que muestra deuda física en pesos, esa va a mostrar `valuationMonetary`. Distinción a documentar en la futura pantalla.
- **Ajuste manual BREAKDOWN de gramos del metal**: sigue apareciendo como `MANUAL_ADJUSTMENT` component del Saldo, no en Patrimonio. Esto es por construcción del motor y se mantiene en R-Rounding-16 sin cambio.
- **Redondeo físico**: aparece como `ROUNDING_MONETARY` component del Saldo (negativo cuando redondeó hacia abajo). Conceptualmente afectó al metal, pero matemáticamente está fuera de `metalCost` (`metalSale = metalCost + monetaryEquivalent_rounding`). El operador lo ve como redondeo del Saldo — cuadra matemáticamente, label podría refinarse a "Redondeo del metal" en futuro.

#### 6. Implementación

Lugares afectados (solo frontend):

- `TotalDelComprobanteCard.tsx` — recibe nueva prop `commercialMetalValueSum`. Cuando viene no-null y BREAKDOWN, recalcula el Saldo Monetario contra `metalCost` (no `valuationMonetary`).
- `MonetarySummary.tsx` — filtro adicional `c.type !== "METAL_MARGIN"` antes del render.
- `MetalsSummary.tsx` — fila al pie del bloque "Valor comercial del metal: ARS X" (cuando se pasa el prop).
- `VentasFacturas.tsx` — pasa `commercialMetalValueSum = documentTotals.metalCostSubtotal` al card.

Lugares **NO afectados**:
- `pricing-engine.*` (motor de cálculo).
- `pricing-engine.balance.ts` (`valuationMonetary` y `monetaryBalance.amount` intactos).
- `balance-mode-runtime.ts` (sigue emitiendo `METAL_MARGIN` component para auditoría).
- DB / Prisma / snapshots.

#### 7. Cumplimiento con §R-Rounding-14

§R-Rounding-14 (contrato canónico DESGLOSADO) define la separación de dominios para **cálculo y persistencia del motor**. §R-Rounding-16 es una **excepción de presentación visual** que **no** modifica los cálculos ni los snapshots. Convive con §R-Rounding-14 sin contradicción:

- A nivel motor / snapshot: §R-Rounding-14 sigue siendo la verdad (metal = físico).
- A nivel UI del card: §R-Rounding-16 prevalece (Patrimonio = comercial).

Cualquier consumer que necesite valuación canónica para auditoría / cuenta corriente / reportes debe seguir leyendo `valuationMonetary` del snapshot, no la cifra mostrada al operador.

---

### §R-Rounding-15 — Etapa D': Migración Comercial PHYSICAL a PER_DOCUMENT (deuda técnica reconocida)

> **Estado actual**: Comercial PHYSICAL opera **PER_UNIT** (`pricing-engine.pricelist.ts:408-414`).
> **Estado objetivo**: Comercial PHYSICAL debe operar **PER_DOCUMENT**, agregado por metal padre, en paralelo arquitectónico con el Financiero capa 16 (§R-Rounding-13).
>
> Decidido y documentado el **2026-05-29** tras auditoría comparativa de las tres granularidades (PER_UNIT / PER_LINE / PER_DOCUMENT) en el caso real `qty=6` con configuración `mode=DECIMAL_1 / direction=NEAREST`. Implementación **diferida** por alcance — no se ejecuta como parte del cierre actual de Factura de Ventas.

#### 1. Estado actual (lo que vive hoy en runtime)

El motor del Comercial PHYSICAL recibe `cost.metalsByParent[i].gramsPure` **POR UNIDAD** del metal padre (`pricing-engine.pricelist.ts:412`) y aplica `roundDocumentMetalGrams` sobre ese valor unitario:

```
pre_unidad  = appliedGrams × purity × (1 + merma/100)
post_unidad = roundToStep(pre_unidad, step, direction)
postGrams_documento = post_unidad × quantity   (escalado posterior, no por el motor)
```

Para `pre_unidad = 1,2375 g`, `step = 0,1`, `NEAREST`:
- `post_unidad = 1,2 g`
- `postGrams_documento(qty=6) = 7,2 g`
- **Físico real** = `qty × pre_unidad = 7,425 g`
- **Delta acumulado** = `−0,225 g` (crece linealmente con `qty`).

#### 2. Estado objetivo (canónico — POLICY §R-Rounding-13 + §R-Rounding-14)

El Comercial PHYSICAL debe replicar la arquitectura del Financiero capa 16:

```
pre_documento  = Σ_líneas( gramsPure_unidad × quantity )    por metal padre
post_documento = roundToStep(pre_documento, step, direction)
```

Para el mismo caso `qty=6`:
- `pre_documento = 7,425 g`
- `post_documento = 7,4 g`
- **Delta acumulado** = `−0,025 g` (acotado estructuralmente a ±step/2 = ±0,05 g, independiente de `qty` y de cantidad de líneas con el mismo padre).

#### 3. Deuda técnica reconocida

| Aspecto | Estado |
|---|---|
| Granularidad real del motor | PER_UNIT (más granular que el "PER_LINE legacy" referenciado en §R-Rounding-14:1214) |
| Granularidad canónica POLICY | PER_DOCUMENT (§R-Rounding-13:769-784 + §R-Rounding-14:1199-1201) |
| Paridad con Financiero capa 16 | ❌ Roto (financiero ya es PER_DOCUMENT, comercial es PER_UNIT) |
| Paridad con Manual Etapa C | ❌ Roto (Manual BREAKDOWN es PER_DOCUMENT) |
| Tests | Deben distinguir explícitamente PER_UNIT vigente vs PER_DOCUMENT canónico |
| Default por tenant | Sin selector — todos los tenants tienen el comportamiento PER_UNIT |
| Decisión funcional | ✅ Tomada (2026-05-29): destino canónico = PER_DOCUMENT |
| Implementación | ⏳ Diferida — Etapa D' (esta sección) |

#### 4. Plan de migración (Etapa D')

Cuando se ejecute (después del cierre de Factura de Ventas):

1. **Schema**: agregar `PriceList.commercialPhysicalRoundingGranularity: "PER_UNIT" | "PER_DOCUMENT"` con default `PER_UNIT` (back-compat).
2. **Motor**: sacar la invocación de `applyCommercialPhysicalRoundingForMetals` de `pricing-engine.pricelist.ts` (per-línea) y crear una capa nueva (paralela a `applyDocumentPhysicalRounding`) que opere a nivel documento. Llamarla desde `computeSaleDocumentTotals` después de la consolidación por metal padre.
3. **Distribución del delta monetario**: definir cómo el `monetaryEquivalent` del redondeo PER_DOCUMENT se refleja en los snapshots de línea (sugerido: emitirlo a nivel documento + flag per-línea "absorbido en el doc"). No reabrir el cálculo del motor de lista.
4. **Anti-doble con Financiero**: cuando ambos están en PER_DOCUMENT con dominio PHYSICAL, mantener la supresión declarada en `schema.prisma:1186-1189` (financiero gana, comercial se suprime).
5. **Snapshots**: nuevo shape `commercialPhysicalRoundingSnapshot` a nivel documento (no per-línea). Migrar consumers frontend (`MonetarySummary.RoundingPhysicalBreakdownRows`, `MetalsSummary`, `TPDocumentLineAdvancedEditor`) para leer del nuevo lugar.
6. **Tests**:
   - Mantener todos los tests `pricelist-commercial-physical.test.ts` y etiquetarlos como "PER_UNIT (legacy)".
   - Crear `pricelist-commercial-physical-per-document.test.ts` con la nueva geometría.
   - Test de paridad: con `qty=1` línea única, PER_UNIT ≡ PER_DOCUMENT (matemáticamente equivalentes para reducir el riesgo de regresión).
7. **Rollout**: tenants nuevos arrancan en PER_DOCUMENT. Tenants existentes migran via toggle UI manual cuando el operador confirme el cambio de comportamiento.

#### 5. Mientras tanto (criterios para frontend / backend nuevos)

- **NO leer directamente** `result.lines[i].appliedRounding.physical.metals[]` para mostrar "postGrams totales del documento". Usar el adapter `aggregateCommercialPostGrams` (`tptech-frontend/src/components/sales/TotalDelComprobanteCard/helpers.ts`) — cuando se migre a PER_DOCUMENT, ese adapter se reescribe en un solo lugar.
- **NO documentar PER_UNIT como contrato funcional**. Cualquier referencia debe etiquetarlo como "comportamiento vigente — destino canónico es PER_DOCUMENT (Etapa D')".
- **NO ampliar la lógica PER_UNIT** con features nuevas (ej. nuevas direcciones, nuevos modos). Toda extensión del redondeo PHYSICAL comercial debe hacerse en la capa nueva (PER_DOCUMENT).
- Para auditoría / soporte al cliente: cuando una venta tenga `qty > 1` y el delta `metalGramsSale` vs `postGrams × qty` sorprenda al operador, explicar como "comportamiento PER_UNIT vigente — destino canónico PER_DOCUMENT pendiente Etapa D'".

#### 6. Trazabilidad

- Decisión registrada: **2026-05-29**.
- Auditoría que originó la decisión: caso `ANILLO SOLITARIO BRILLANTE`, `qty=6`, `DECIMAL_1 NEAREST`.
- Cumplimiento POLICY:
  - §R-Rounding-13:769-784 → comercial PHYSICAL debe operar a nivel documento (sigue legacy).
  - §R-Rounding-14:1199-1201 → los tres mecanismos deben respetar la misma separación (financiero ya cumple, comercial no).
  - §R-Rounding-14:1214 → estado de cumplimiento del comercial: ⚠️ Legacy.
  - §R-Rounding-15 (esta sección) → trayectoria de migración formal.

---

## §Tax & Discounts Pipeline — modelo fiscal oficial TPTech

**Política oficial:** todo descuento comercial que reduzca el valor efectivo de
venta del comprobante debe reducir proporcionalmente la `taxableBase` **y** el
`taxAmount`. Sin excepciones para impuestos porcentuales. Para impuestos de
monto fijo (`FIXED_AMOUNT`), aplica una excepción explícita (ver §Tax.5).

### §Tax.1 — Orden oficial del pipeline fiscal/comercial

Este orden es **inmutable**. Cualquier desvío produce divergencias entre
`taxableBase` y `taxAmount` y rompe el modelo fiscal del comprobante.

| # | Capa | Dónde se aplica | Sobre qué base | Modifica `lineTotal` | Modifica `taxableBase` | Modifica `taxAmount` |
|---|---|---|---|---|---|---|
| 1 | Costo | `pricing-engine.cost.ts` | — | — | — | — |
| 2 | Margen + lista / precio manual | `pricing-engine.pricelist.ts` | costo | ✅ | ✅ | ✅ vía línea |
| 3 | Promoción de línea | `pricing-engine.sale.ts` | basePrice | ✅ | ✅ | ✅ vía línea |
| 4 | Descuento por cantidad | `pricing-engine.sale.ts` | post-promoción | ✅ | ✅ | ✅ vía línea |
| 5 | Descuento de cliente / surcharge | `pricing-engine.sale.ts` | post-cantidad | ✅ | ✅ | ✅ vía línea |
| 6 | Descuento manual de línea | `pricing-engine.sale.ts` | post-cliente | ✅ | ✅ | ✅ vía línea |
| 7 | **`computeLineTaxes()`** — tax por línea | `pricing-engine.sale.ts:543` | `finalPrice` de línea | — | — | computa `lineTaxAmount` |
| 8 | Canal de venta | `pricing-engine.channel.ts` | `subtotalAfterLineDiscounts` | ❌ | ✅ | ✅ vía scaling (§Tax.4) |
| 9 | Cupón | `pricing-engine.coupon.ts` | post-canal | ❌ | ✅ | ✅ vía scaling (§Tax.4) |
| 10 | Bonificación global del documento | `computeSaleDocumentTotals` input | post-cupón | ❌ | ✅ | ✅ vía scaling (§Tax.4) |
| 11 | **`taxableBase`** = `subtotalAfterLineDiscounts + canal − cupón − global` | `document.ts:755` | — | — | resultado | — |
| 12 | **`taxAmount`** efectivo (porcentual scaled + fixed) | `document.ts` §Tax.4 | `lineTaxTotal` × ratio | — | — | resultado |
| 13 | Envío | `document.ts` | suma directa | — | — | — |
| 14 | Forma de pago | `document.ts` | suma directa post-tax | — | — | — |
| 15 | Redondeo del comprobante (Etapa 1B) | `document.ts` | `total` | — | — | — |
| 16 | (futuro) Ajuste manual final | ETAPA 2 | `total` | — | — | — |
| 17 | Total final | — | resultado | — | — | — |
| 18 | Snapshot inmutable (cabecera + por línea) | `Sale.documentFiscalSnapshot` + `Receipt.pricingSnapshot` | — | — | — | — |

### §Tax.2 — Regla fiscal oficial

> Todo descuento comercial que reduzca el valor real de venta del comprobante
> — descuento global, cupón, canal con ajuste negativo, descuento doc futuro —
> debe reducir proporcionalmente **`taxableBase`** Y **`taxAmount`**. El
> escalado se aplica una sola vez, a nivel documento, mediante
> `effectiveSaleRatio` (ver §Tax.4).

Razones:
1. Modelo fiscal correcto: si la base imponible cae, el IVA cae con ella.
2. Cuenta corriente correcta: el cliente no debe saldo "fantasma" de IVA.
3. PDF correcto: el comprobante impreso refleja la realidad fiscal.
4. Auditabilidad: un solo número (`effectiveDiscountRatio`) explica el ajuste.

### §Tax.3 — Excepción: impuestos `FIXED_AMOUNT`

Los impuestos con `calculationType = "FIXED_AMOUNT"` (percepciones, sellados,
tasas regulatorias, cargos fijos) **no escalan** con descuentos comerciales:

- Existen independientemente del valor comercial — son montos absolutos.
- Una percepción de $100 no se reduce a $50 porque el operador bonificó 50%.
- El componente fijo se separa del componente porcentual y se suma sin scaling.

Los impuestos `PERCENTAGE_PLUS_FIXED` se tratan como suma de las dos
componentes: la parte porcentual escala, la fija no. El caller debe reportar
ambas porciones por separado a `computeSaleDocumentTotals`.

### §Tax.4 — Fórmula oficial de scaling

Calculada **una vez por documento**, en `computeSaleDocumentTotals` después
de armar `taxableBase` y antes de computar el `total`:

```
subtotalAfterLineDiscounts = Σ lineTotal                       // post-línea
taxableBase                = max(0, subtotalAfterLineDiscounts
                                    + canal − cupón − global)  // §Tax.1 paso 11

// Ratio de venta efectiva (1.0 = sin descuento doc; 0.0 = descuento total)
effectiveSaleRatio =
  subtotalAfterLineDiscounts > 0
    ? max(0, taxableBase) / subtotalAfterLineDiscounts
    : 0

effectiveDiscountRatio = 1 − effectiveSaleRatio                // para snapshot

// Separación PERCENTAGE vs FIXED — el caller la provee por línea
scalableLineTaxTotal = Σ (lineTaxAmount − lineTaxAmountFixed)
fixedLineTaxTotal    = Σ lineTaxAmountFixed

scaledScalableTax    = round2(scalableLineTaxTotal × effectiveSaleRatio)
taxAmount            = round2(scaledScalableTax + fixedLineTaxTotal)
```

**Edge cases:**
- `subtotalAfterLineDiscounts = 0` → `effectiveSaleRatio = 0` → todo el tax
  porcentual cae a 0; los fijos siguen.
- `taxableBase < 0` (clamp a 0) → el descuento doc supera el subtotal post-línea
  → `effectiveSaleRatio = 0` → mismo tratamiento.
- `taxableBase = subtotalAfterLineDiscounts` → `effectiveSaleRatio = 1` → sin
  scaling, comportamiento idéntico al pre-fix. **Esto garantiza back-compat
  cuando no hay canal/cupón/global activos.**

### §Tax.5 — Lo que NO se recalcula

El scaling **solo opera a nivel documento**. Está **prohibido**:

- Recalcular `lineTaxAmount` per-línea tras aplicar el descuento global.
- Mutar `SaleLine.pricingSnapshot.taxAmount` post hoc.
- Pasar el descuento global como input a `computeLineTaxes` (rompería el
  modelo de pasada única del motor de líneas).
- Distribuir el descuento global a las líneas como pseudo-descuento de línea.

El snapshot **por línea** queda con la realidad pre-doc-discounts; el snapshot
**de cabecera** (`Sale.documentFiscalSnapshot`) refleja el scaling aplicado.

### §Tax.6 — Trazabilidad obligatoria

Toda venta con `effectiveSaleRatio < 1.0` debe persistir en
`Sale.documentFiscalSnapshot`:

```ts
{
  effectiveSaleRatio:       number,   // 0.0 a 1.0
  effectiveDiscountRatio:   number,   // 1 - effectiveSaleRatio
  subtotalAfterLineDiscounts: number,
  taxableBase:              number,
  originalTaxAmount:        number,   // suma sin scaling (legacy)
  scalableTaxAmount:        number,   // total porcentual pre-scaling
  fixedTaxAmount:           number,   // total fijo (no escala)
  scaledScalableTax:        number,   // total porcentual post-scaling
  scaledTaxAmount:          number,   // = scaledScalable + fixed (= Sale.taxAmount)
  scalingApplied:           boolean,  // false cuando ratio = 1.0
}
```

Si el snapshot está `null` o `scalingApplied = false`, el documento no tuvo
descuentos de cabecera y el `taxAmount` coincide con la suma de
`lineTaxAmount`.

### §Tax.7 — Compatibilidad y deprecaciones

- **`Sale.discountAmount`** sigue persistiendo solo el descuento del cupón
  (`legacyCouponOnlyDiscount`). Marcado como **legacy** — no agregar nuevos
  consumidores. Reportes financieros nuevos deben usar
  `documentFiscalSnapshot.documentDiscountTotalAmount` o el snapshot de
  Receipt.
- **`Sale.taxAmount`** queda como número final post-scaling (compatible con
  todos los consumers: PDF, cuenta corriente, mail).
- Callers de `computeSaleDocumentTotals` que **no** pasen `lineTaxAmountFixed`
  por línea siguen funcionando: el motor asume `fixed = 0` → todo el tax
  escala. Comportamiento correcto para tenants con solo IVA porcentual.

### §Tax.8 — Tests obligatorios

`pricing-engine/__tests__/document-totals.test.ts` y
`sales/__tests__/preview-confirm-parity.test.ts` deben cubrir:

1. `globalDiscount = 10% / 50% / 100%` sobre línea con IVA 21%.
2. `globalDiscount` combinado con cupón y canal.
3. `cliente exento` + `globalDiscount` (esperado: tax = 0 sin ambigüedad).
4. Impuesto `FIXED_AMOUNT` ($100 percepción) + `globalDiscount` 100%
   (esperado: taxableBase = 0, taxAmount = 100, total = 100).
5. Impuesto `PERCENTAGE_PLUS_FIXED` (IVA 21% + sellado fijo) + global.
6. BREAKDOWN rounding + global (Etapa 1B + Tax).
7. BOTH rounding + global.
8. Paridad preview ↔ confirm con todos los casos anteriores.
9. PDF lee el `total` correcto (no el inflado).
10. `CurrentAccountMovement.amountBase` igual al snapshot.

---

## Vigencia y proceso de cambio

Esta política se actualiza solo con:

1. Aprobación explícita del owner del producto.
2. Bump de `snapshotVersion` si el cambio afecta persistencia.
3. Tests de paridad antes/después en el mismo PR.
4. Update simultáneo de `pricing-engine/README.md` y `CLAUDE.md`.

Cualquier código fusionado que la viole es bug y debe revertirse.
