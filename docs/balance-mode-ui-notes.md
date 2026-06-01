# Balance Mode — Notas de UX para Fase 4

> Documento de **preparación**. NO contiene implementación: lista las
> decisiones de diseño visual a tomar y los puntos de integración que
> tienen que existir en el frontend cuando se aborde la Fase 4.
>
> Fase 3B.8 dejó el sistema end-to-end funcional pero **no integró** el
> componente visual en la pantalla de Factura. La integración requiere
> decisiones de UX que están listadas acá.

---

## 1. Punto de integración principal: `VentasFacturas.tsx`

El preview ya devuelve `balanceMode`, `balanceModeSource` y `balanceBreakdown`
en el response de `salesApi.preview(...)`. El componente
`<TPSaleBalanceSummary>` está listo en
`tptech-frontend/src/components/sales/TPSaleBalanceSummary.tsx` y se enchufa
así:

```tsx
import { TPSaleBalanceSummary } from "../../components/sales/TPSaleBalanceSummary";

// Dentro del render de VentasFacturas, cerca del bloque de TotalsHero:
<TPSaleBalanceSummary
  balanceMode={backendPreview?.balanceMode}
  balanceBreakdown={backendPreview?.balanceBreakdown}
  currencyCode={backendPreview?.responseCurrencyCode}
/>
```

Si `backendPreview` no trae `balanceBreakdown` (caller legacy o error), el
componente NO renderiza nada — no rompe el flujo.

---

## 2. Convivencia con `<TPDocumentTotalsHero>`

### Opciones de layout

**Opción A — Reemplazo condicional**

Si `balanceMode === "BREAKDOWN"`, el Hero clásico se reemplaza por el
TPSaleBalanceSummary (que internamente tiene su propia versión visual del
saldo monetario). Una sola región, dos modos.

Pros:
- UX consistente con la metáfora "Saldo del documento".
- Sin duplicación visual del TOTAL.

Contras:
- Requiere que `TPSaleBalanceSummary` cubra **toda** la información que hoy
  muestra Hero (subtotal, descuentos, impuestos, total). Hoy sólo muestra
  TOTAL/SALDO MONETARIO.

**Opción B — Coexistencia visual** _(recomendada como punto de partida)_

Mantener `TPDocumentTotalsHero` como hoy (mostrando subtotal → descuentos →
impuestos → total). Agregar `TPSaleBalanceSummary` como **bloque
separado** debajo del Hero, expandido cuando el modo es BREAKDOWN.

```
[Subtotal]   $ ......
[Descuentos] $ ......
[Impuestos]  $ ......
[Total]      USD 1.250        ← TPDocumentTotalsHero (legacy)
─────────────────────────────
METALES                       ← TPSaleBalanceSummary (nuevo)
Oro Fino      1,526 gr
Plata         0,350 gr
SALDO MONETARIO
USD 91,25
```

En modo UNIFIED el `TPSaleBalanceSummary` puede ocultarse o mostrarse como
single-line "TOTAL = SALDO MONETARIO".

Pros:
- Cero riesgo de regresión visual del Hero existente.
- Operador ve los totales tradicionales + el desglose por separado.

Contras:
- Posible redundancia de "TOTAL" en ambos bloques (mismo número).

### Decisión sugerida

**Opción B** como entrada — luego, si el operador da feedback de que la
redundancia molesta, evaluar **Opción A** colapsando el Hero en BREAKDOWN.

---

## 3. Pantalla de cuenta corriente

La API `commercialEntitiesApi.getBalanceMovements(entityId, params)` está
lista y devuelve:

```ts
{
  data: BalanceMovementDTO[],   // con metalEntries[] hidratadas
  total: number,
  skip:  number,
  take:  number,
}
```

### Decisiones de UX

1. **¿Reutilizar `EntityAccountStatement.tsx` o crear nueva pantalla?**
   - El statement legacy lee `EntityBalanceEntry` y muestra opening/closing
     balance por metal + hechura. La API nueva trae movimientos con shape
     distinto (gramos por padre + saldo monetario + trazabilidad).
   - **Sugerencia**: agregar un toggle/tab en `EntityAccountStatement`:
     "Vista legacy" (actual) vs "Vista canónica" (`balance-movements`).
     Hasta deprecar `EntityBalanceEntry`, ambas conviven.

2. **"Ver origen"** — cada `BalanceMovementDTO` trae
   `sourceDocumentType` y `sourceDocumentId`. Cuando el operador hace clic
   en el movimiento, navegar a la pantalla correspondiente:
   - `SALE` → modal/pantalla de Venta `sale-${id}`.
   - `PURCHASE` → pantalla de Compra (cuando exista runtime hook).
   - `CROSS_SETTLEMENT` → pantalla de liquidación.

3. **Render del movimiento BREAKDOWN**:
   ```
   [Movimiento DEBIT]              [Origen: VTA-0001]
   ────────────────────────────────────────────────
   Metales:
     • Oro Fino     1,526 gr  (Pureza: 0,763)
     • Plata        0,350 gr  (Pureza: 0,925)
   Saldo monetario: USD 91,25
   Fecha: 22/05/2026
   ```

4. **Render del movimiento UNIFIED** (default histórico + flujos sin metal):
   ```
   [Movimiento DEBIT]              [Origen: VTA-0001]
   USD 1.250                                          22/05/2026
   ```

---

## 4. Override manual de `balanceMode` en Factura

Hoy `previewSale` acepta `input.balanceModeOverride` pero `createSale` /
`updateSale` no lo persisten en `Sale.balanceModeOverride` (que existe
como columna en DB pero queda null por defecto). Esto significa que un
override seteado en preview se pierde si el operador guarda como DRAFT y
vuelve después.

### Decisiones pendientes

1. **¿UI permite override?** — Sugerencia: badge clickeable en el header
   de la factura: "Saldo: UNIFIED [cambiar]" → modal con UNIFIED/BREAKDOWN
   + "Auto (heredar de cliente)".
2. **Persistencia DRAFT** — extender `createSale` / `updateSale` para
   aceptar y persistir `balanceModeOverride`. Es un campo trivial
   (BalanceMode? nullable) y ya está en schema.
3. **Visibilidad de `balanceModeSource`** — el frontend recibe el source
   ("ENTITY_DEFAULT", etc.) en el preview. UX puede mostrar un tooltip
   "¿De dónde sale este modo?" cuando el operador hace hover sobre el
   badge UNIFIED/BREAKDOWN.

---

## 5. Multi-moneda final

El backend ya convierte los campos monetarios del breakdown
(`monetaryBalance.amount`, `metals[].valuationMonetary`,
`components[].amount`) a la moneda del documento via
`convertBalanceBreakdownInPlace`. Los gramos NO se convierten.

### Decisiones UX

1. **Display de "≈ X ARS"** (referencial) — cuando el documento está en
   USD, el operador puede querer ver el equivalente en pesos para
   conciliar con balance de tenant. `monetaryBalance.amountBase` ya viaja
   en BASE; mostrar entre paréntesis: `USD 91,25 (≈ AR$ 91.250)`.
2. **Cotización snapshot en el movimiento** — `currencyRate` viaja en el
   DTO; mostrar como tooltip "Tipo de cambio al confirmar: 1 USD = 1.000 ARS".
3. **Valuación referencial del metal** — `metals[].valuationMonetary` ya
   se convierte a moneda doc. Mostrar como secundario:
   `Oro Fino  1,526 gr  (≈ USD 152,60)`.

---

## 6. Estados de carga / error

El componente `TPSaleBalanceSummary` es 100% read-only. Si el preview falla:

- `usePreviewFlow` ya maneja el toast de error y el chip "Totales sin
  actualizar".
- `TPSaleBalanceSummary` simplemente mostrará el último `balanceBreakdown`
  cacheado en `backendPreview` (cache del hook).

No requiere lógica adicional.

---

## 7. Mobile-first

El componente respeta `mobile-first`:
- `vt.row.flexBetween` ya es responsive (flex container).
- Las filas de metal usan `<ul>` lineal, no tabla — viable en 375px.
- Sin tablas horizontales que comprometan iPhone SE.

A validar en QA cuando se integre.

---

## 8. Tests visuales sugeridos para Fase 4

Cuando se integre en `VentasFacturas.tsx`, agregar tests E2E o de
integración que cubran:

1. **Smoke**: factura UNIFIED se renderiza completa con `TPSaleBalanceSummary`.
2. **Smoke**: factura BREAKDOWN muestra metales + saldo monetario.
3. **Multi-moneda**: factura en USD muestra "USD" en monto, gramos sin cambio.
4. **Cambio de modo**: cambiar override de UNIFIED a BREAKDOWN en preview
   → la UI re-renderiza el bloque correcto.
5. **Cliente sin balance preset**: factura cae a tenant default UNIFIED y
   muestra el bloque correspondiente.
6. **Cliente legacy con balanceType=BREAKDOWN y balanceMode=null**: cae a
   `mapBalanceTypeToMode` y muestra BREAKDOWN (R11.14).

---

## 9. Decisión pendiente: deprecación dura de `balanceType`

Hoy `CommercialEntity.balanceType` (legacy) coexiste con `balanceMode`
(canónico). El runtime ya prefiere `balanceMode` y cae a `balanceType`
solo cuando es null. UX sugerida para migración:

1. **Fase A (no breaking)** — en la pantalla de edición de cliente,
   reemplazar el select que escribe `balanceType` por uno que escribe
   `balanceMode`. Lectura sigue priorizando `balanceMode`.
2. **Fase B (data migration)** — script one-shot que, para cada cliente con
   `balanceMode = null`, lo setea con `mapBalanceTypeToMode(balanceType) ?? null`.
3. **Fase C (cleanup destructivo)** — quitar `balanceType` del schema +
   borrar `mapBalanceTypeToMode` + actualizar tests.

Decisión de timing pendiente. NO bloquea Fase 4.

---

## 10. Glosario rápido

| Término | Definición |
|---|---|
| **Balance Mode** | UNIFIED vs BREAKDOWN — cómo se persiste el saldo del documento en cuenta corriente. |
| **UNIFIED** | Saldo monetario único. `metals=[]`. |
| **BREAKDOWN** | Saldo dividido entre gramos por metal padre + saldo monetario consolidado. |
| **gramsPure** | Unidad canónica de acumulación = `gramsOriginal × purity`. |
| **Pureza ponderada** | `Σ(g_i × p_i) / Σ g_i` cuando un padre agrupa varias variantes. |
| **Ver origen** | Navegación desde un `CurrentAccountMovement` al `Sale`/`Purchase` que lo generó via `sourceDocumentType` + `sourceDocumentId`. |
| **Snapshot v3** | Versión actual de `DocumentPricingSnapshot` con `balanceMode`, `balanceModeSource`, `balanceBreakdown`. |
| **Legacy v2** | Snapshots pre-3B.3 — leídos como UNIFIED implícito via `readBalanceBreakdown`. |
