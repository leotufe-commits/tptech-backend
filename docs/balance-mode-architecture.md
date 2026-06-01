# Balance Mode — Arquitectura canónica

> **Estado**: documentación canónica congelada en Fase 1. Sin implementación todavía.
> **Última actualización**: 2026-05-22.
> **Documento vinculante**: cualquier implementación futura debe cumplir lo definido acá. Las reglas resumidas viven en `src/lib/pricing-engine/POLICY.md` §11.

---

## 1. Resumen ejecutivo

TPTech opera dos modelos canónicos de saldo para todos los documentos comerciales (venta, compra, recibo, ajuste, liquidación cruzada):

- **`UNIFIED`** — un único saldo monetario en la moneda activa.
- **`BREAKDOWN`** — saldo separado por metal padre en gramos puros, más un único saldo monetario consolidado que absorbe todo lo demás.

El `balanceMode` se resuelve automáticamente por prioridad y puede ser sobreescrito manualmente en el documento. Se congela en el snapshot al confirmar.

Saldos históricos pre-implementación permanecen UNIFIED. La migración no recalcula nada del pasado.

---

## 2. Modelos canónicos

### 2.1 UNIFIED

Definición:

- El documento se expresa en **una sola moneda activa** (la `currency` del documento).
- Internamente el motor sigue calculando metal/hechura para auditoría y display, pero **el saldo persistido en cuenta corriente es un único monto monetario**.
- Movimiento de cuenta corriente: 1 fila en `CurrentAccountMovement`, `metalEntries = []`.
- Frontend: card "Composición del total" oculto por defecto, accesible vía ⓘ (consulta contextual).

Cuándo aplica:

- Default histórico (todos los tenants antes de la implementación de BREAKDOWN).
- Listas de precios `MARGIN_TOTAL`, `MANUAL`, cualquiera que no exponga buckets metal/hechura desagregados.
- Clientes/proveedores marcados como `UNIFIED` o sin política explícita.

Ejemplo:

```
Documento:           Factura 0001 ARS
Subtotal:            ARS 470.000
Descuento:          −ARS  10.000
IVA 21%:             ARS  96.600
─────────────────────────────────
TOTAL:               ARS 556.600

Cuenta corriente:
  DEBIT  ARS 556.600  (movimiento único)
```

### 2.2 BREAKDOWN

Definición:

- El documento se desglosa en **dos dimensiones canónicas independientes**:
  1. Una colección `metals[]` de saldos en **gramos puros por metal padre**.
  2. Un único `monetaryBalance` consolidado en la moneda activa.
- **Invariante R11.2**: el `monetaryBalance` absorbe **todo lo que no es metal** (hechura, productos, servicios, impuestos, ajustes, redondeos, envíos, cupones, canal, forma de pago, costos financieros).
- Movimiento de cuenta corriente: 1 fila en `CurrentAccountMovement` con `monetaryAmount` + N filas en `AccountMovementMetalEntry` (una por metal padre presente).
- Frontend: card "Composición del total" visible por defecto.

Cuándo aplica:

- Listas de precios `METAL_HECHURA`, `COST_PER_GRAM`, las que desglosan buckets.
- Clientes/proveedores marcados como `BREAKDOWN`.
- Tenants con `defaultBalanceMode = BREAKDOWN`.
- Selección manual del operador en el documento.

Ejemplo:

```
Documento:           Factura 0001 ARS, modo BREAKDOWN
Composición:
  Oro Fino           1,526 gr (gramos puros)
                   ARS 381.562,50 (display secundario)
  Plata             4,340 gr
                   ARS  17.890,00 (display secundario)
  Hechura/IVA/etc   ARS  91.911,47 (saldo monetario)

Cuenta corriente:
  DEBIT  Oro Fino:        1,526 gr
  DEBIT  Plata:           4,340 gr
  DEBIT  Saldo monetario: ARS 91.911,47
```

---

## 3. Invariantes

### 3.1 Identidad metal

```
gramsPure = gramsOriginal × purity
```

`gramsPure` es la **unidad canónica de acumulación** en cuenta corriente. `gramsOriginal` y `purity` se persisten como snapshot para reproducibilidad histórica (si la pureza catalogada cambia después, el saldo histórico no se altera).

### 3.2 Composición del total

Para cualquier documento en modo BREAKDOWN:

```
TotalLínea     = Σ(metalValue_i) + monetaryBalance
metalValue_i   = gramsPure_i × quotePrice_i (valorización al momento de confirmar)
```

Donde `quotePrice_i` es la cotización snapshot del metal padre en el momento de confirmación. La valorización en moneda se persiste **como display histórico** (no como saldo principal — el saldo principal son los gramos).

Para `UNIFIED`:

```
TotalLínea = monetaryBalance (único)
metals[] = []
```

### 3.3 IVA / impuestos = saldo monetario

**Sin excepción** (R11.3). Aunque `applyOn=METAL` en el motor, el monto resultante del impuesto suma a `monetaryBalance`, nunca a `metals[]`.

Justificación: fiscalmente AFIP/equivalente acepta sólo monto monetario. `applyOn` define la base de cálculo, no el destino del impuesto.

### 3.4 Saldo monetario incluye explícitamente

```
monetaryBalance = (
  + hechura(s)
  + productos
  + servicios
  + impuestos (IVA, percepciones, retenciones)
  + recargos (manuales, automáticos, por cantidad, etc.)
  + ajustes manuales del operador
  + redondeos monetarios
  + envíos
  ± canal de venta (recargo/descuento)
  ± forma de pago (recargo/descuento)
  ± costos financieros
  − bonificaciones (automáticas y manuales)
  − cupones
  − descuentos del cliente
  − promociones
)
```

---

## 4. Prioridad de resolución de `balanceMode`

Orden estricto, primer match gana:

| # | Fuente | Campo | Notas |
|---|---|---|---|
| 1 | Override manual del documento | `Sale.balanceModeOverride` (nuevo) | Operador selecciona en el header del documento. Sólo permitido antes de confirmar. |
| 2 | Default del cliente/proveedor | `CommercialEntity.balanceMode` (nuevo) | Política comercial: este cliente opera en metal. |
| 3 | Default de la lista de precios | `PriceList.balanceMode` (nuevo) | Listas `METAL_HECHURA` típicamente BREAKDOWN; `MARGIN_TOTAL` típicamente UNIFIED. |
| 4 | Default del tenant | `Jewelry.defaultBalanceMode` (nuevo) | Última red. Default global del tenant. |

Si todos son `null`, el sistema asume `UNIFIED` (regla de retrocompatibilidad).

Una vez resuelto y persistido en el snapshot al confirmar, el `balanceMode` es **inmutable** (R11.5).

---

## 5. Trazabilidad

### 5.1 De movimiento → documento

Cada `CurrentAccountMovement` persiste:

```
sourceDocumentType  : SALE | PURCHASE | RECEIPT | ADJUSTMENT | CROSS_SETTLEMENT
sourceDocumentId    : id del documento origen
```

### 5.2 De entrada metálica → línea origen

Cada `AccountMovementMetalEntry` adicionalmente persiste:

```
sourceLineId        : FK a SaleLine.id / PurchaseLine.id (según source)
```

### 5.3 "Ver origen" (UX)

El frontend debe ofrecer un disclosure por movimiento que muestre:

- Documento origen completo (`sourceDocumentType` + `sourceDocumentId`).
- Por cada línea del documento:
  - `composition.metals[]` (gramos por variante + padre).
  - `composition.hechuras/products/services[]`.
  - Ajustes monetarios aplicados (promo, qty discount, bonif manual, recargo, IVA, redondeos).
- Para cada `metalEntry` del movimiento: link directo a la `sourceLine` específica.

Endpoint backend canónico (futuro):

```
GET /current-account-movements/{movementId}/origin
→ { document, lines: [{ line, composition, adjustments }] }
```

---

## 6. Snapshot v6 — shape propuesto

> Cambio versionado de `snapshotVersion = 5 → 6`. Snapshots v5 o anteriores se leen como UNIFIED implícito (back-compat).

### 6.1 `DocumentPricingSnapshot` (top-level del documento)

```ts
type DocumentPricingSnapshot = {
  // ── existentes (compat v5) ──
  version: 6;                                  // bump
  resolvedAt: ISO8601;
  totals: SnapshotTotals;
  rounding: SnapshotRounding;

  // ── nuevo v6 ──
  balanceMode: "UNIFIED" | "BREAKDOWN";        // congelado al confirmar
  balanceModeSource:                            // de dónde salió el valor
    | "DOCUMENT_OVERRIDE"
    | "ENTITY_DEFAULT"
    | "PRICELIST_DEFAULT"
    | "TENANT_DEFAULT"
    | "FALLBACK_UNIFIED";

  // En UNIFIED: { metals: [], monetaryBalance: totals.totalWithTax }
  // En BREAKDOWN: distribución real.
  balanceBreakdown: {
    metals: Array<{
      metalParentId:    string;
      metalParentName:  string;                // snapshot — supervive a renames
      gramsOriginal:    number;
      purity:           number;
      gramsPure:        number;                // = gramsOriginal × purity
      quotePriceSnapshot: number | null;       // valorización al confirmar (display)
      sourceLineIds:    string[];              // líneas que aportaron este metal
    }>;
    monetaryBalance:  number;                  // siempre en moneda del documento
    monetaryCurrency: string;                  // code (ARS/USD/etc.)
  };

  // Trazabilidad — id congelado del documento que generó el snapshot.
  sourceDocumentType: "SALE" | "PURCHASE" | "RECEIPT" | "ADJUSTMENT" | "CROSS_SETTLEMENT";
  sourceDocumentId:   string;
};
```

### 6.2 `DocumentLineSnapshot` (por línea)

Cambios mínimos. La línea SIGUE persistiendo `metalHechuraBreakdown` como antes; sumar:

```ts
type DocumentLineSnapshot = {
  ...existentes;

  // ── nuevo v6 ──
  // Aporte de esta línea al balance del documento, ya distribuido entre
  // metal y monetario según `balanceMode`. Para UNIFIED, `metals=[]` y
  // `monetaryContribution = lineTotalWithTax`.
  lineBalanceContribution: {
    metals: Array<{ metalParentId: string; gramsPure: number; gramsOriginal: number; purity: number }>;
    monetaryContribution: number;     // en moneda del documento
  };
};
```

### 6.3 Helper canónico del motor

```ts
// pricing-engine.balance.ts — extender
buildBalanceBreakdownForDocument(
  documentSnapshot: DocumentPricingSnapshot,
  mode: BalanceMode,
): {
  metals:           BalanceMetalItem[];
  monetaryBalance:  number;
  monetaryCurrency: string;
}
```

Este helper es **derivado** del snapshot (lee — no calcula). En UNIFIED devuelve `metals: []` y `monetaryBalance = totals.totalWithTax`.

---

## 7. Persistencia — modelos a crear

> Solo definición conceptual. No se crea schema ni migración en Fase 1.

### 7.1 Cambios en modelos existentes

```
Jewelry {
  + defaultBalanceMode: BalanceMode @default(UNIFIED)
}

PriceList {
  + balanceMode: BalanceMode?            // null = heredar del tenant
}

CommercialEntity {
  + balanceMode: BalanceMode?            // null = heredar de lista o tenant
}

Sale, Purchase, Receipt, CrossSettlement {
  + balanceMode: BalanceMode             // congelado al confirmar
  + balanceModeOverride: BalanceMode?    // override del operador (pre-confirmación)
  + balanceModeSource: BalanceModeSource // de dónde salió (para auditoría)
}

CurrentAccountMovement {
  + balanceMode: BalanceMode @default(UNIFIED)
  + monetaryAmount: Decimal(14, 4)       // renombre de amountBase para claridad
  + sourceDocumentType: SourceDocumentType
  + sourceDocumentId: String?
  + metalEntries: AccountMovementMetalEntry[]
}
```

### 7.2 Modelos nuevos

```
enum BalanceMode {
  UNIFIED
  BREAKDOWN
}

enum BalanceModeSource {
  DOCUMENT_OVERRIDE
  ENTITY_DEFAULT
  PRICELIST_DEFAULT
  TENANT_DEFAULT
  FALLBACK_UNIFIED
}

enum SourceDocumentType {
  SALE
  PURCHASE
  RECEIPT
  ADJUSTMENT
  CROSS_SETTLEMENT
}

model AccountMovementMetalEntry {
  id                  String   @id @default(cuid())
  movementId          String                                // FK CurrentAccountMovement
  metalParentId       String                                // FK MetalVariant (id del padre conceptual)
  metalParentName     String                                // snapshot
  gramsOriginal       Decimal  @db.Decimal(14, 4)
  purity              Decimal  @db.Decimal(7, 6)
  gramsPure           Decimal  @db.Decimal(14, 4)
  quotePriceSnapshot  Decimal? @db.Decimal(14, 4)           // display histórico
  sourceLineId        String?                                // FK opcional a línea origen
  createdAt           DateTime @default(now())

  movement            CurrentAccountMovement @relation(...)

  @@index([movementId])
  @@index([metalParentId])
  @@index([movementId, metalParentId])                       // saldo por cliente × metal
}
```

**Por qué tabla relacional y no JSON** (decisión confirmada):

- Queries de saldo (`SUM(gramsPure) WHERE entityId = X AND metalParentId = Y`) son O(N) con índice; con JSON serían escaneo completo + parseo.
- Validación de tipos por Prisma (no se puede insertar un saldo con purity inválida).
- Permite extender la entrada (agregar campos futuros) sin reparsear JSON histórico.
- Compatible con joins para "ver origen" sin deserialización.

---

## 8. Migración

### 8.1 Estrategia de no-tocar-saldos-viejos (R11.8)

- Movimientos existentes (pre-Fase-2): conservan su shape actual. Al agregar la columna `balanceMode`, default `UNIFIED`. `metalEntries = []` (vacío). Saldo del cliente histórico = sumatoria de `monetaryAmount` (= `amountBase` renombrado) — idéntico al saldo pre-migración.
- Movimientos nuevos (post-Fase-2): pueden ser `BREAKDOWN`. Tienen entradas metálicas explícitas.
- Coexisten en la misma tabla. La pantalla de cuenta corriente debe agrupar visualmente:
  - Saldo monetario (suma de `monetaryAmount` de TODOS los movimientos).
  - Saldo por metal (suma de `gramsPure` de los movimientos BREAKDOWN, agrupados por `metalParentId`).

### 8.2 Snapshot version bump

- v5 → v6: agregar campos nuevos. Lectura tolerante en frontend/reports: si `version < 6`, asumir `balanceMode = UNIFIED`, `balanceBreakdown.metals = []`, `monetaryBalance = totals.totalWithTax`.
- Tests de paridad antes/después: snapshots v5 producidos pre-migración deben seguir mostrando el saldo idéntico post-migración (`monetaryBalance` derivado = `totalWithTax` original).

### 8.3 Endpoints — compatibilidad

- `sales/preview`, `confirmSale`: agregan `balanceMode` opcional al input. Default = resolución automática. Response incluye `balanceBreakdown` derivado del snapshot.
- Endpoint nuevo: `GET /commercial-entities/{id}/account-statement?mode=UNIFIED|BREAKDOWN` — modo de presentación independiente del modo de cada movimiento (puede agrupar movimientos BREAKDOWN para mostrarlos como UNIFIED por compatibilidad de impresión legacy).

---

## 9. Fases de implementación

### Fase 1 — Documentación (ESTA fase)

- ✅ Definir y documentar reglas canónicas.
- ✅ Agregar §11 a `pricing-engine/POLICY.md`.
- ✅ Crear este documento de arquitectura.
- ⏭️ No tocar schema ni código funcional.
- ⏭️ No crear migraciones.

### Fase 2 — Schema y modelos (próxima)

- Bump `snapshotVersion` a 6 en types.
- Agregar `enum BalanceMode` y `enum BalanceModeSource` en Prisma.
- Agregar columnas `balanceMode` a `Jewelry`, `PriceList`, `CommercialEntity`, `Sale`, `Purchase`, `Receipt`, `CrossSettlement`, `CurrentAccountMovement`.
- Crear tabla `AccountMovementMetalEntry`.
- Migración Prisma con defaults seguros (`UNIFIED` para todos los registros existentes; `metalEntries = []` por defecto).
- Tests de regresión: saldos históricos calculados antes/después de la migración deben coincidir byte a byte.

### Fase 3 — Preview / confirm

- `pricing-engine` extiende el snapshot v6 con `balanceMode`, `balanceModeSource`, `balanceBreakdown`.
- `previewSale`, `confirmSale`, equivalentes de compra, ajuste, etc.: resuelven `balanceMode` por prioridad, lo persisten en snapshot, devuelven `balanceBreakdown` en response.
- Hook `onSaleConfirmed`: cuando `balanceMode === BREAKDOWN`, crear las `metalEntries` derivadas del snapshot. Cuando `UNIFIED`, solo el monetario (comportamiento actual).
- Tests obligatorios:
  - Paridad preview ↔ confirm en ambos modos.
  - IVA siempre suma a `monetaryBalance`.
  - `Σ metals[i].gramsPure` estable bajo qty / promo / manualPrice / bonif / recargo.
  - Snapshots v5 cargados producen saldo idéntico al `monetaryBalance` derivado.

### Fase 4 — Cuenta corriente UI

- Endpoint `GET /commercial-entities/{id}/account-statement?mode=...`.
- Pantalla `FinanzasCuentaCorriente.tsx` conectada (hoy mock).
- Vistas:
  - Modo UNIFIED: tabla de movimientos con `debit/credit/balance` en una sola moneda (compatible con flujo actual).
  - Modo BREAKDOWN: agrupa por metal (gramos) + monetario (dinero). Saldo total = N saldos en gramos + 1 saldo en moneda.
- Disclosure "Ver origen" por movimiento.
- Card "Composición del total" en el item de Factura: visible por defecto si documento es BREAKDOWN, oculto-on-demand si UNIFIED.

### Fase 5 — Cobranza en metal (futuro, separado)

- `Receipt` recibe pagos en metal (entrega física de gramos).
- `ReceiptMetalApplication` (tabla nueva): aplica gramos contra movimientos previos.
- Política de conversión cross-purity: cuando cliente paga Au 18k para saldar deuda en Au 999, definir factor de conversión.
- Allocation contra movimientos DEBIT pendientes por metal.

---

## 10. Casos de uso documentados

### 10.1 Venta UNIFIED a cliente sin lista metal

```
Cliente:            "Juan" (balanceMode null)
Lista de precios:   "Minorista" (balanceMode UNIFIED)
Tenant:             defaultBalanceMode UNIFIED

Resolución:         UNIFIED (fuente PRICELIST_DEFAULT)
Confirmación:       1 movimiento CurrentAccountMovement con monetaryAmount=556.600 ARS
                    metalEntries=[]
```

### 10.2 Venta BREAKDOWN — multi-metal

```
Cliente:            "Joyería del Centro" (balanceMode BREAKDOWN)
Lista:              "Mayorista Metal_Hechura"

Resolución:         BREAKDOWN (fuente ENTITY_DEFAULT)

Documento:
  Línea 1 → Anillo Oro 18k. Composición: 5g Oro 18k (purity 0.75), hechura ARS 80.000.
  Línea 2 → Pulsera Plata. Composición: 12g Plata 925 (purity 0.925), hechura ARS 15.000.
  IVA 21%: ARS 19.950 (sobre hechura total).

Snapshot:
  balanceMode: BREAKDOWN
  balanceBreakdown.metals = [
    { metalParentId: "oro-fino", gramsPure: 3.75 (=5×0.75), gramsOriginal: 5, purity: 0.75 },
    { metalParentId: "plata-925", gramsPure: 11.1 (=12×0.925), gramsOriginal: 12, purity: 0.925 },
  ]
  monetaryBalance: 80.000 + 15.000 + 19.950 = 114.950 ARS

Confirmación → CurrentAccountMovement:
  DEBIT, monetaryAmount=114.950 ARS
  metalEntries = [
    { metalParentId: "oro-fino",  gramsPure: 3.75,  sourceLineId: "L1" },
    { metalParentId: "plata-925", gramsPure: 11.1,  sourceLineId: "L2" },
  ]
```

### 10.3 Override manual del operador

```
Cliente:            "Cliente VIP" (balanceMode BREAKDOWN)
Documento:          operador eligió UNIFIED en el header (intención fiscal).

Resolución:         UNIFIED (fuente DOCUMENT_OVERRIDE)

Confirmación:       1 movimiento monetario único.
                    El motor internamente computa metal/hechura para
                    auditoría (snapshot), pero las metalEntries quedan
                    vacías porque el modo del documento es UNIFIED.
```

### 10.4 Cliente con saldo mixto (post-migración)

```
Cliente "X":
  Movimiento histórico v5 (pre-migración):
    DEBIT ARS 500.000, balanceMode=UNIFIED, metalEntries=[]
  Movimiento nuevo v6 (post-migración):
    DEBIT 3.75 gr Oro Fino + ARS 114.950, balanceMode=BREAKDOWN

Saldo agregado del cliente:
  · Monetario:  ARS 614.950 (500.000 + 114.950)
  · Oro Fino:   3.75 gr puros

No se recalcula nada del pasado.
```

### 10.5 IVA sobre metal — saldo monetario (R11.3)

```
Documento BREAKDOWN.
Cliente con tax override: 21% applyOn=METAL.

Composición:
  Línea: 5g Oro 18k, valor metal $400.000, hechura $80.000.
  IVA 21% sobre la BASE metal ($400.000) = $84.000.

Snapshot:
  balanceBreakdown.metals = [{ gramsPure: 3.75, ... }]
  monetaryBalance: 80.000 (hechura) + 84.000 (IVA) = 164.000 ARS

→ IVA NO se convierte a gramos. Cae 100% en saldo monetario.
→ La base del cálculo fue metal, pero el destino del impuesto es monetario.
```

---

## 11. Decisiones congeladas

1. **R11.3 — IVA siempre monetario**, sin excepción, aunque `applyOn=METAL`.
2. **Tabla relacional `AccountMovementMetalEntry`** (no JSON) para permitir queries de saldo eficientes.
3. **Históricos UNIFIED por default**, sin recalcular. Coexisten con movimientos BREAKDOWN nuevos.
4. **Resolución por prioridad** documento → cliente → lista → tenant → fallback UNIFIED.
5. **Override manual permitido SOLO antes de confirmar**. Una vez confirmado, `balanceMode` es inmutable.
6. **Receipts metálicos (cobranza)**: separado, Fase 5. No bloquea Fase 2-4.

---

## 12. Referencias cruzadas

- `src/lib/pricing-engine/POLICY.md` §11 — reglas resumidas R11.1 a R11.10.
- `src/lib/pricing-engine/pricing-engine.balance.ts` — `buildBalanceBreakdownFromPrice` (existente, extender en Fase 3).
- `src/lib/pricing-engine/pricing-engine.document.ts` — `buildDocumentPricingSnapshot` (extender shape en Fase 3).
- `prisma/schema.prisma` — modelos a tocar listados en §7 (Fase 2).
- `src/modules/sales/sales.service.ts` — `previewSale`/`confirmSale` extender en Fase 3.
- `src/lib/document-hooks/sale.hook.ts` — `onSaleConfirmed` extender en Fase 3.
- `tptech-frontend/src/pages/FinanzasCuentaCorriente.tsx` — conectar en Fase 4.

---

## 13. Vigencia

Este documento se actualiza solo con:

1. Aprobación explícita del owner del producto.
2. Bump de versión documental al inicio del archivo.
3. Actualización simultánea de POLICY.md §11 si la regla cambia.
4. Tests de paridad antes/después en el mismo PR que toque la regla.

Cualquier implementación que viole estas reglas es bug y debe revertirse.

---

## 14. Estado al cierre de Fase 3B.8 (snapshot del sistema)

> Esta sección refleja el sistema **end-to-end funcional** tras 8 sub-fases incrementales.
> Antes de leer "TODO Fase 4 UX/UI", validar que la implementación actual
> sigue cumpliendo R11.1 → R11.15.

### 14.1 Flujo runtime completo

```
ENTRADA (frontend)
   │
   │ draft.balanceModeOverride? (opcional)
   ▼
POST /api/sales/preview  ─────────────────────────────────────────────────┐
   │                                                                     │
   ▼                                                                     │
previewSale (sales.service.ts)                                           │
   │ 1. carga clientRow (balanceType legacy + balanceMode canónico)      │
   │ 2. resuelve líneas + costos (motor habitual)                        │
   │ 3. captura costBreakdown[] por índice de línea                      │
   │ 4. computeSaleDocumentTotals                                        │
   │ 5. carga priceList.balanceMode (try/catch defensive)                │
   │ 6. carga jewelry.defaultBalanceMode (try/catch defensive)           │
   │ 7. resolveSaleBalanceMode({...}) → BalanceModeResolution            │
   │ 8. si BREAKDOWN: batch query Metal+MetalVariant names               │
   │ 9. buildSaleBalanceBreakdown(mode, totals, lines, names)            │
   │ 10. response payload con balanceMode/Source/Breakdown               │
   │                                                                     │
   ▼                                                                     │
convertSalesPreviewResponseInPlace(res, rate)                            │
   │ + convertBalanceBreakdownInPlace(bd, rate)                          │
   │   · monetary.amount / metals.valuationMonetary se DIVIDEN por rate  │
   │   · gramsOriginal / gramsPure / purity NUNCA se tocan               │
   │   · amountBase / currencyRate NUNCA se tocan                        │
   │                                                                     │
   ▼                                                                     │
FRONTEND consume                                                         │
   · TPSaleBalanceSummary lee balanceBreakdown del response              │
   · UNIFIED → "TOTAL <moneda> <monto>"                                  │
   · BREAKDOWN → "METALES" gramos + "SALDO MONETARIO" en moneda doc      │
                                                                         │
─────────────────────────────────────────────────────────────────────────┘

POST /api/sales/:id/confirm
   │
   ▼
confirmSale (sales.service.ts)
   │ 1-2. snapshots costo/impuesto/comisión por línea (lineResults)
   │ 3. computeSaleDocumentTotals
   │ 4-6. mismo flujo de Balance Mode que preview, sobre lineResults
   │ 7. tx.sale.update({ ..., balanceMode, balanceModeSource })  ← CONGELADO
   │ 8. onSaleConfirmed(tx, id, { balanceMode, balanceModeSource, balanceBreakdown })
   │
   ▼
sale.hook.onSaleConfirmed
   │ 1. loadSale
   │ 2. buildSnapshotInputFromSale + inyectar balanceMode/Source/Breakdown
   │ 3. buildDocumentPricingSnapshot → snapshot v3 con balanceBreakdown real
   │ 4. crea Receipt + ReceiptLine (snapshot v3 viaja en pricingSnapshot)
   │ 5. valida isValidBalanceBreakdownForPersistence (R11.12)
   │ 6. tx.currentAccountMovement.create({
   │      ..., balanceMode, sourceDocumentType="SALE", sourceDocumentId=sale.id,
   │      amountBase = monetaryBalance.amountBase si BREAKDOWN,
   │    })
   │ 7. si BREAKDOWN + metales válidos:
   │      tx.accountMovementMetalEntry.createMany(rows)
   │      (rows pasan por buildAccountMovementMetalEntryRows con dedup +
   │       filtro NaN/Infinity/≤0)
```

### 14.2 Snapshot v3 final

`DOCUMENT_SNAPSHOT_VERSION = 3` (técnico). El bloque nuevo respecto a v2:

```ts
{
  version: 3,
  // ...todos los campos pre-existentes (totals, lines, currency, etc.)
  balanceMode:       "UNIFIED" | "BREAKDOWN",
  balanceModeSource: "DOCUMENT_OVERRIDE" | "ENTITY_DEFAULT" |
                     "PRICELIST_DEFAULT" | "TENANT_DEFAULT" | "FALLBACK_UNIFIED",
  balanceBreakdown: {
    metals: DocumentBalanceMetalEntry[],   // [] en UNIFIED
    monetaryBalance: {
      amount: number,         // moneda del documento
      amountBase: number,     // moneda BASE del tenant
      currencyCode: string,
      currencyRate: number,
      components?: DocumentBalanceMonetaryComponent[],  // display-only
    },
  },
  sourceDocument?: { kind: "SALE" | "PURCHASE" | ..., id: string, number?: string },
}
```

Lectura tolerante: `readBalanceBreakdown(snapshot)` devuelve siempre un breakdown consumible + `source` ("SNAPSHOT_V3" | "LEGACY_UNIFIED" | "INVALID").

### 14.3 Cuenta corriente híbrida

`CurrentAccountMovement` (modelo canónico):
- `balanceMode` (default UNIFIED).
- `sourceDocumentType` / `sourceDocumentId` (R11.7).
- `amountBase` / `amountOriginal` / `currencyCode` / `currencyRate` siempre.
- `metalEntries[]` relación 1-N (creada solo en BREAKDOWN).

`AccountMovementMetalEntry`:
- Una fila por metal padre por movimiento BREAKDOWN.
- `gramsOriginal`, `purity` (ponderada), `gramsPure` (canónico).
- `metalParentName` snapshot al confirmar (inmutable).
- `sourceLineId` único cuando 1 sola línea aportó.

`EntityBalanceEntry` (legacy): coexiste sin tocar. Lectura legacy via `account-statement.service`; lectura canónica nueva via `balance-movements.service` (Fase 3B.7).

### 14.4 Invariantes finales blindadas

| # | Regla | Cobertura runtime |
|---|---|---|
| R11.1 | gramsPure canónico | `buildDocumentBalanceBreakdown` + `buildAccountMovementMetalEntryRows` |
| R11.2 | monetary absorbe todo no-metal | `documentTotal − Σ metalLineValuationDocCurrency` |
| R11.3 | IVA siempre monetario | passthrough del motor — no tocado |
| R11.4 | Prioridad documento → entity → list → tenant → fallback | `resolveSaleBalanceMode` |
| R11.5 | Inmutabilidad post-confirm | `Sale.balanceMode` set una sola vez en `tx.sale.update` |
| R11.6 | Persistencia por modo | hook crea metalEntries solo en BREAKDOWN |
| R11.7 | Trazabilidad sourceDocumentType/Id | hook setea siempre |
| R11.8 | Históricos quedan UNIFIED | `readBalanceBreakdown` LEGACY_UNIFIED |
| R11.9 | Snapshot v3 obligatorio | `DOCUMENT_SNAPSHOT_VERSION = 3` |
| R11.10 | Frontend read-only | `TPSaleBalanceSummary` no calcula |
| R11.11 | Defensive on grams | `buildAccountMovementMetalEntryRows` filtra NaN/Inf/≤0 |
| R11.12 | Defensive on monetary | `isValidBalanceBreakdownForPersistence` rechaza NaN/Inf |
| R11.13 | Dedupe metal padre | `buildAccountMovementMetalEntryRows` consolida por padre |
| R11.14 | `balanceType` deprecado | `@deprecated` en helpers + types frontend |
| R11.15 | Histórico inmutable | `readBalanceBreakdown` no recompone metals |

### 14.5 Fallback legacy

| Situación | Comportamiento |
|---|---|
| `CommercialEntity.balanceMode === null` y `balanceType` legacy presente | `mapBalanceTypeToMode` lo traduce — R11.14 |
| Snapshot v1 / v2 sin `balanceBreakdown` | `readBalanceBreakdown` → `LEGACY_UNIFIED` con `monetary.amount = totals.total` |
| `CurrentAccountMovement` viejo sin `balanceMode` | `projectBalanceMovement` defaultea a UNIFIED, `metalEntries: []` |
| `balanceType` con string ajeno al enum | `mapBalanceTypeToMode` → null → baja al siguiente nivel R11.4 |
| Frontend sin `balanceBreakdown` en preview | `TPSaleBalanceSummary` no renderiza (back-compat) |

### 14.6 Responsabilidades

| Capa | Decide | Calcula | Lee |
|---|---|---|---|
| `pricing-engine` (motor) | precios/descuentos/impuestos | sí | costo/cotizaciones |
| `resolveSaleBalanceMode` | balanceMode resuelto | no (solo prioridad) | clientRow/priceList/jewelry |
| `buildSaleBalanceBreakdown` | shape del breakdown | no (proyección pura) | lineResults/totals |
| `sale.hook` | persistencia cuenta corriente | no (passthrough del breakdown) | snapshot + opts |
| `convert*InPlace` | display currency | no (división por rate) | rate del response |
| frontend `TPSaleBalanceSummary` | nada | no (formatea) | preview |
| frontend `balanceMovementsApi` | nada | no | DB via DTO |

---

## 15. TODOs restantes para Fase 4 UX y posteriores

### Fase 4 — UX/UI definitiva

- [ ] Integrar `<TPSaleBalanceSummary>` en `VentasFacturas.tsx`. Posición sugerida en `docs/balance-mode-ui-notes.md`.
- [ ] Convivencia con `<TPDocumentTotalsHero>`: definir cuál muestra UNIFIED y cuál BREAKDOWN, o si comparten una sola región condicional. Ver UX notes.
- [ ] Crear pantalla / panel para listar `CurrentAccountMovement` con `metalEntries[]` y "Ver origen" navegable a Sale.
- [ ] Persistir `Sale.balanceModeOverride` desde `createSale` / `updateSale` (hoy `previewSale` lo acepta del input pero el DRAFT no lo guarda).
- [ ] UI: selector de balanceMode override por documento (Factura).
- [ ] UI: ajustes en `EntityAccountStatement` o creación de pantalla paralela usando `getBalanceMovements`.

### Fase 4+ (sub-fases independientes)

- [ ] **Receipts metálicos**: setear `Receipt.balanceMode` (campo ya existe). Cobranza en gramos (Fase 5 planificada).
- [ ] **Conciliación metálica**: queries de saldo agregado por metal padre por cliente.
- [ ] **Dashboards / reportes**: KPIs históricos por tipo de saldo.
- [ ] **Print/PDF**: factura impresa con bloque BREAKDOWN.
- [ ] **Migración legacy `balanceType` → `balanceMode`**: data migration + eliminación de campo (R11.14 cierre).
- [ ] **Cross-flow**: aplicar mismo patrón a Purchase y CrossSettlement (los campos ya existen en schema, falta runtime).
- [ ] **Currency conversion en confirmSale**: hoy confirmSale persiste en BASE; cuando confirmemos en moneda no-base, extender `convertBalanceBreakdownInPlace` al snapshot persistido.

### Riesgos abiertos

1. **`metalLineValuationDocCurrency` con descuentos sobre metal**: confirmSale lo deriva de `breakdownSnapshot.totals.metal × quantity`. Si el motor aplica descuentos/recargos sobre metal post-snapshot, esa valuación puede divergir levemente. **Mitigación**: capturar el `metalSale` exacto de `deriveMetalHechuraBreakdown` en `lineResults` (sub-fase futura).
2. **Listas múltiples ("MIXED")**: `priceListBalanceModeDefault = null` y cae a tenant. Documentar en UX que cuando hay varias listas el operador puede explicitar `balanceModeOverride`.
3. **Currency conversion del snapshot persistido**: snapshots almacenados están en BASE; si en el futuro persistimos en moneda no-base, hay que reconvertir en lectura o persistir ambos.
4. **`balanceType` coexistencia indefinida**: hasta hacer data-migration, los clientes con `balanceType=BREAKDOWN` y `balanceMode=null` siguen activos via fallback. Documentar en CLAUDE.md cuando se agende la migración.

