# Arquitectura de Comprobantes, Cuenta Corriente y Pagos

**Estado:** diseño. NO implementado. No migrar aún.
**Alcance:** Fase 4 del plan de blindaje. Prepara el terreno para que comprobantes, cuenta corriente y pagos entren al sistema sin duplicar lógica de precios y sin tocar el pricing-engine.
**Fecha:** 2026-04-23.

---

## 1. Principios rectores

1. **El pricing-engine es la única fuente de verdad de cálculo comercial.** Comprobantes, cuenta corriente y pagos **leen** snapshots; nunca recalculan precios, impuestos, descuentos, canal o medio de pago.
2. **Los comprobantes son documentos históricos inmutables.** Una vez emitidos no se editan. Las correcciones se hacen emitiendo otro comprobante (nota de crédito / nota de débito).
3. **La cuenta corriente es un libro mayor.** Sólo se alimenta de comprobantes emitidos y pagos aplicados. Nunca se escribe “a mano”.
4. **Sale / Purchase son transacciones operativas. Receipt es un documento fiscal.** Una transacción puede generar 0..N comprobantes (típicamente: presupuesto y después factura + remito).
5. **Todo cálculo nuevo entra al pricing-engine.** Si un comprobante necesita un dato (ej: desglose metal/hechura, total con impuestos), el motor lo expone en el snapshot o se extiende el motor.

---

## 2. Capa 1 — `PricingSnapshot` unificado

### 2.1 Qué hay hoy

El motor ya expone dos interfaces en `src/lib/pricing-engine/pricing-engine.types.ts`:

- `PricingLineSnapshot` — foto del precio de una línea de venta (precio, base, descuento, impuestos, origen, costo, margen).
- `CostSnapshot` — foto del costo de una línea de compra.

`SaleLine.pricingSnapshot` y `PurchaseLine.pricingSnapshot` ya son columnas `Json?` que guardan estas fotos. Funciona bien a nivel línea.

### 2.2 Lo que falta cubrir

El snapshot de línea no captura el **contexto del comprobante completo**: canal de venta, cupón, medio de pago, plan de cuotas, moneda+cotización, emisor, receptor, tipo de ítem consolidado.

Hoy eso vive en campos sueltos de `Sale` (`channelSnapshot`, `couponSnapshot`, `currencySnapshot`, `issuerSnapshot`, `clientSnapshot`, `sellerSnapshot`). Eso va a duplicarse si lo movemos “tal cual” al Receipt. Necesitamos **un solo snapshot de cabecera** consumible desde cualquier comprobante.

### 2.3 Nuevo tipo `DocumentPricingSnapshot`

Extiende el concepto ya existente y agrupa todo lo que se congela al confirmar:

```ts
// En src/lib/pricing-engine/pricing-engine.types.ts

export interface DocumentPricingSnapshot {
  // ── Identidad del snapshot ───────────────────────────────────────────────
  version:    number;         // 1 por ahora; bump si cambia el shape
  resolvedAt: string;         // ISO-8601 del momento en que se congeló

  // ── Contexto de moneda (SIEMPRE presente) ────────────────────────────────
  // Se guarda por valor (currencyCode + currencyRate) en vez de por FK para
  // garantizar reconstrucción exacta aunque la moneda se elimine o renombre.
  currency: {
    id:             string;
    currencyCode:   string;       // "ARS", "USD", "EUR"
    symbol:         string;
    /** Cotización de la moneda de la transacción a la moneda base del tenant.
     *  Usada para convertir amountBase en toda la cadena documento→mayor→pago. */
    currencyRate:   number;
    /** Código de la moneda base del tenant al momento del snapshot */
    baseCurrencyCode: string;
  };

  // ── Partes ───────────────────────────────────────────────────────────────
  issuer: {
    jewelryId:    string;
    name:         string;
    cuit:         string;
    ivaCondition: string;
  };
  counterparty: {
    entityId:     string | null;   // CommercialEntity
    kind:         "CLIENT" | "SUPPLIER";
    displayName:  string;
    docType:      string;
    docNumber:    string;
    ivaCondition: string;
  } | null;                        // null = consumidor final

  // ── Capas comerciales aplicadas (todas opcionales) ───────────────────────
  channel: {
    id:   string;
    name: string;
    adjustmentPercent: number | null;
    adjustmentAmount:  number;      // monto resuelto por el motor
  } | null;

  coupon: {
    id:             string;
    code:           string;
    name:           string;
    discountType:   "FIXED" | "PERCENTAGE";
    discountValue:  number;
    discountAmount: number;         // monto resuelto
  } | null;

  /** Promoción aplicada (prioridad más alta del motor).
   *  Puede haber más de una a nivel línea → se repite en DocumentLineSnapshot.
   *  Este campo es solo informativo a nivel cabecera. */
  promotion: {
    id:             string;
    name:           string;
    type:           "FIXED" | "PERCENTAGE";
    value:          number;
    priority:       number;
  } | null;

  /** Descuento por cantidad aplicado a nivel cabecera (si hay agrupación). */
  quantityDiscount: {
    id:     string;
    name:   string;
    tier:   number;
  } | null;

  paymentMethod: {
    id:               string;
    name:             string;
    type:             string;       // CASH | CARD | TRANSFER | METAL | CHECK | OTHER
    surchargePercent: number | null;
    installmentsQty:  number;
    installmentsPlan: { id: string; name: string } | null;
    surchargeAmount:  number;
  } | null;

  // ── Redondeo aplicado (el motor lo resuelve, aquí se congela) ───────────
  rounding: {
    /** Origen del redondeo: lista de precios, política del tenant, manual. */
    source:    "PRICE_LIST" | "TENANT_POLICY" | "MANUAL" | "NONE";
    /** A qué base se aplicó: LINE (por línea), NET (subtotal post descuentos),
     *  TOTAL (importe final con impuestos), METAL / HECHURA (componentes). */
    appliedOn: "LINE" | "NET" | "TOTAL" | "METAL" | "HECHURA" | "NONE";
    mode:      "INTEGER" | "DECIMAL_1" | "DECIMAL_2" | "TEN" | "HUNDRED" | "NONE";
    direction: "UP" | "DOWN" | "NEAREST" | "NONE";
    /** Diferencia absoluta introducida por el redondeo sobre el importe previo */
    adjustment: number;
  };

  // ── Desglose de impuestos a nivel cabecera ──────────────────────────────
  // Suma de los taxBreakdown de cada línea, agrupada por impuesto.
  taxBreakdown: Array<{
    taxId:           string;
    name:            string;
    code:            string;
    taxType:         string;          // IVA | INTERNAL | PERCEPTION | RETENTION | OTHER
    calculationType: "PERCENTAGE" | "FIXED_AMOUNT" | "PERCENTAGE_PLUS_FIXED";
    applyOn:         string;          // TOTAL | METAL | HECHURA | SUBTOTAL_* | METAL_Y_HECHURA
    rate:            number | null;
    fixedAmount:     number | null;
    baseAmount:      number;          // base sobre la que se aplicó
    taxAmount:       number;          // monto del impuesto
    baseEstimated:   boolean;         // true si la base se derivó proporcionalmente
    overriddenByEntity: boolean;      // true si la entidad aplicó override
  }>;

  // ── Totales congelados (moneda del documento) ───────────────────────────
  totals: {
    subtotal:         number;   // suma de lineTotal antes de canal/cupón/pago
    channelAmount:    number;
    couponAmount:     number;
    quantityDiscountAmount: number;
    promotionAmount:  number;
    paymentSurcharge: number;
    discountAmount:   number;   // suma de descuentos comerciales (cupón + promo + qty)
    taxAmount:        number;
    roundingAdjustment: number; // diferencia introducida por redondeo (puede ser ±)
    total:            number;   // importe final a cobrar / pagar
    totalBase:        number;   // total convertido a moneda base
  };

  // ── Costos agregados (para cálculo de margen histórico) ─────────────────
  // Permite reportes de margen sin depender del costo actual del catálogo.
  cost: {
    totalCost:     number | null;     // Σ unitCost × quantity de líneas no-COMBO
    totalMargin:   number | null;     // totals.subtotal - totalCost
    marginPercent: number | null;     // (totalMargin / subtotal) × 100
    costPartial:   boolean;           // true si alguna línea no tiene costo resuelto
  };

  // ── Líneas (fotos individuales) ──────────────────────────────────────────
  lines: DocumentLineSnapshot[];
}

export interface DocumentLineSnapshot extends PricingLineSnapshot {
  // PricingLineSnapshot ya aporta: unitPrice, basePrice, discountAmount,
  //   taxAmount, totalWithTax, priceSource, baseSource, unitCost, unitMargin,
  //   marginPercent, costPartial, costMode, appliedPriceListId/Name,
  //   appliedPromotionId/Name, appliedDiscountId, resolvedAt, partial.
  // Acá se extiende con identidad, combo, cantidad y desglose por línea.

  // ── Identidad del ítem vendido / comprado ────────────────────────────────
  itemKind:    "ARTICLE_SIMPLE" | "ARTICLE_VARIANT" | "SERVICE" | "COMBO";
  articleId:   string;
  variantId:   string | null;
  code:        string;
  sku:         string;
  barcode:     string;
  name:        string;           // display final (incluye nombre de variante)

  // ── Si el ítem es combo, fotografía de componentes ───────────────────────
  comboComponents?: Array<{
    articleId: string;
    code:      string;
    name:      string;
    quantity:  number;
    unitCost:  number | null;
    affectsStock: boolean;
  }>;

  // ── Cantidad y totales de la línea ───────────────────────────────────────
  quantity:     number;
  subtotal:     number;          // unitPrice × quantity (antes de descuento de línea)
  discountLine: number;          // descuento aplicado a esta línea (cupón/promo/qty proporcional)
  lineTotal:    number;          // subtotal - discountLine (antes de impuestos de línea)
  lineTaxAmount:number;          // impuestos aplicados a esta línea
  lineTotalWithTax: number;      // lineTotal + lineTaxAmount

  // ── Costo congelado de la línea ──────────────────────────────────────────
  totalCost:    number | null;   // unitCost × quantity (ya está en PricingLineSnapshot como unitCost; se duplica total)
  totalMargin:  number | null;   // lineTotal - totalCost

  // ── Desglose de impuestos por línea ─────────────────────────────────────
  taxBreakdown: Array<{
    taxId:       string;
    name:        string;
    rate:        number | null;
    fixedAmount: number | null;
    baseAmount:  number;
    taxAmount:   number;
  }>;

  // ── Desglose Metal/Hechura por línea (si aplica) ────────────────────────
  metalHechuraBreakdown?: {
    metalCost:      number;
    metalSale:      number;
    hechuraCost:    number;
    hechuraSale:    number;
    metalGramsBase: number | null;
  } | null;
}
```

### 2.4 Reglas de inmutabilidad

- Una vez que `resolvedAt` se setea, **nada en el snapshot cambia**.
- El snapshot se construye con un helper del motor: `buildDocumentPricingSnapshot(opts)` — el único lugar autorizado a armar la estructura.
- Los servicios de Receipt / CurrentAccount / Payment **no** construyen snapshots por su cuenta. Piden al motor.
- Si se emite una nota de crédito / débito sobre un documento previo, se **copia** el snapshot con ajustes explícitos (ver capa 2).

### 2.5 Dónde se guarda

- En la cabecera del documento (`Receipt.pricingSnapshot: Json`).
- Redundancia controlada: los `DocumentLineSnapshot` también se guardan en cada `ReceiptLine.pricingSnapshot` para hacer queries line-level sin parsear el JSON completo.

---

## 3. Capa 2 — Comprobantes (`Receipt` / `ReceiptLine`)

### 3.1 Qué es un comprobante

Un documento fiscal/legal que representa una operación confirmada. Tiene numeración controlada (presupuestos + facturas + notas), tipo enumerado, y snapshot de precio. **No** es una vista de una venta: puede haber múltiples comprobantes por venta.

### 3.2 Tipos soportados

Enum `ReceiptType`:

| Tipo | Dirección | Afecta cuenta corriente | Afecta stock |
|---|---|---|---|
| `QUOTE` (presupuesto) | salida | No | No |
| `INVOICE` (factura) | salida o entrada | **Sí (DEBIT para ventas, CREDIT para compras de la joyería)** | Sí |
| `DELIVERY_NOTE` (remito) | salida o entrada | No | Sí |
| `CREDIT_NOTE` (nota de crédito) | salida o entrada | Sí (compensa) | Opcional (devolución) |
| `DEBIT_NOTE` (nota de débito) | salida o entrada | Sí (suma) | No |

Las reglas “afecta stock” / “afecta cuenta corriente” son del tipo, no se pueden configurar por instancia. Eso elimina ambigüedad histórica.

### 3.3 Relación con Sale / Purchase

- Un `Receipt` tiene FK opcional a `Sale` o a `Purchase` (`saleId` / `purchaseId`). Nunca ambos.
- Un `Sale` puede generar varios `Receipt` (típico: QUOTE → INVOICE + DELIVERY_NOTE → eventualmente CREDIT_NOTE).
- Los totales del `Receipt` son independientes de los totales del `Sale` — el `Receipt` conserva sus propios números históricos aunque el `Sale` se cancele.

### 3.4 Corrección: nota de crédito / débito

- Nunca se edita un comprobante confirmado. Para corregir:
  - **Crédito comercial** (devolución parcial, bonificación post-venta) → emitir `CREDIT_NOTE` que referencia al `Receipt` original (`correctedReceiptId`).
  - **Débito comercial** (carga adicional, interés por mora) → emitir `DEBIT_NOTE` idem.
- La nota **no** copia ni recalcula el snapshot completo: construye uno nuevo usando el motor con los ítems/importes correctivos.
- La nota **compensa** el saldo en cuenta corriente (ver capa 3).

### 3.5 Numeración

- Por tenant + por tipo + por punto de venta (un `ReceiptSeries` que define prefijo y próximo número).
- Atómica bajo transacción (ya existe este patrón en `ArticleMovement` codes — reusar).

### 3.6 Shape sugerido de Prisma

```prisma
enum ReceiptType {
  QUOTE
  INVOICE
  DELIVERY_NOTE
  CREDIT_NOTE
  DEBIT_NOTE
}

enum ReceiptDirection {
  OUTBOUND   // la joyería emite (venta)
  INBOUND    // la joyería recibe (compra)
}

enum ReceiptStatus {
  DRAFT       // pre-confirmado, editable
  ISSUED      // confirmado, inmutable
  VOIDED      // anulado (solo para DRAFT o INVOICE sin pagos)
}

model Receipt {
  id          String            @id @default(cuid())
  jewelryId   String
  seriesId    String            // FK a ReceiptSeries
  code        String            // "A-0001-00000123" formateado
  type        ReceiptType
  direction   ReceiptDirection
  status      ReceiptStatus     @default(DRAFT)

  // ── Operación que originó el comprobante ────────────────────────────────
  saleId      String?           // exclusivo con purchaseId
  purchaseId  String?

  // ── Documento que corrige (solo CREDIT_NOTE / DEBIT_NOTE) ───────────────
  correctedReceiptId String?

  // ── Partes (snapshots + FK débil) ───────────────────────────────────────
  counterpartyId String?        // CommercialEntity

  // ── Snapshot congelado (DocumentPricingSnapshot) ────────────────────────
  pricingSnapshot Json          // inmutable después de status=ISSUED

  // ── Snapshot de moneda (congelado al emitir) ────────────────────────────
  // Se guarda por valor para reconstrucción exacta aunque la moneda se elimine.
  // Siempre debe coincidir con pricingSnapshot.currency pero se duplica en
  // columnas planas para indexar y filtrar sin deserializar JSON.
  currencySnapshot   Json        // { id, currencyCode, symbol, currencyRate, baseCurrencyCode, resolvedAt }
  currencyCode       String      @default("")
  currencyRate       Decimal     @default(1) @db.Decimal(18, 8)  // a moneda base

  // ── Totales planos (redundantes pero útiles para queries) ───────────────
  subtotal        Decimal @default(0) @db.Decimal(14, 2)
  discountAmount  Decimal @default(0) @db.Decimal(14, 2)
  taxAmount       Decimal @default(0) @db.Decimal(14, 2)
  total           Decimal @default(0) @db.Decimal(14, 2)
  totalBase       Decimal @default(0) @db.Decimal(14, 2)         // total × currencyRate

  // ── Fechas ──────────────────────────────────────────────────────────────
  issueDate   DateTime          @default(now())
  dueDate     DateTime?         // para facturas a plazo
  issuedAt    DateTime?         // set cuando pasa a ISSUED
  voidedAt    DateTime?
  voidReason  String            @default("")
  notes       String            @default("")

  issuedById  String?
  voidedById  String?
  createdAt   DateTime          @default(now())
  updatedAt   DateTime          @updatedAt

  jewelry            Jewelry              @relation(fields: [jewelryId], references: [id], onDelete: Cascade)
  series             ReceiptSeries        @relation(fields: [seriesId], references: [id], onDelete: Restrict)
  sale               Sale?                @relation(fields: [saleId], references: [id], onDelete: Restrict)
  purchase           Purchase?            @relation(fields: [purchaseId], references: [id], onDelete: Restrict)
  correctedReceipt   Receipt?             @relation("ReceiptCorrections", fields: [correctedReceiptId], references: [id], onDelete: Restrict)
  corrections        Receipt[]            @relation("ReceiptCorrections")
  counterparty       CommercialEntity?    @relation(fields: [counterpartyId], references: [id], onDelete: SetNull)
  lines              ReceiptLine[]
  accountMovements   CurrentAccountMovement[]
  paymentAllocations PaymentAllocation[]

  @@unique([jewelryId, seriesId, code])
  @@index([jewelryId, type])
  @@index([jewelryId, status])
  @@index([counterpartyId])
  @@index([saleId])
  @@index([purchaseId])
  @@index([correctedReceiptId])
}

model ReceiptLine {
  id        String  @id @default(cuid())
  receiptId String
  jewelryId String

  // ── Snapshot por línea (DocumentLineSnapshot completo) ───────────────────
  pricingSnapshot Json

  // ── Campos planos duplicados desde el snapshot ──────────────────────────
  // Se persisten columnas Decimal espejadas del snapshot para habilitar:
  //   · reportes SQL sin deserializar JSON,
  //   · índices por ítem,
  //   · filtros/ordenamientos en listados.
  // REGLA: estos campos se escriben UNA sola vez al emitir el comprobante
  // y nunca se recalculan. El snapshot sigue siendo la fuente autoritativa
  // en caso de disputa o reconstrucción.
  articleId  String?
  variantId  String?
  itemKind   String                 // ARTICLE_SIMPLE | ARTICLE_VARIANT | SERVICE | COMBO
  name       String  @default("")
  code       String  @default("")
  sku        String  @default("")
  barcode    String  @default("")

  // Precio y cantidad
  quantity   Decimal @db.Decimal(14, 4)
  unitPrice  Decimal @db.Decimal(14, 4)

  // Totales de línea (duplicados del snapshot)
  subtotal      Decimal @db.Decimal(14, 2)   // unitPrice × quantity
  discountAmount Decimal @default(0) @db.Decimal(14, 2)  // descuentos aplicados a la línea
  lineTotal     Decimal @db.Decimal(14, 2)   // subtotal - discountAmount
  taxAmount     Decimal @default(0) @db.Decimal(14, 2)   // impuestos de la línea
  totalWithTax  Decimal @db.Decimal(14, 2)   // lineTotal + taxAmount (total pagable de la línea)

  // Costo y margen (para reportes)
  totalCost     Decimal? @db.Decimal(14, 2)
  totalMargin   Decimal? @db.Decimal(14, 2)

  sortOrder  Int      @default(0)
  createdAt  DateTime @default(now())

  receipt Receipt         @relation(fields: [receiptId], references: [id], onDelete: Cascade)
  article Article?        @relation(fields: [articleId], references: [id], onDelete: SetNull)
  variant ArticleVariant? @relation(fields: [variantId], references: [id], onDelete: SetNull)

  @@index([receiptId])
  @@index([articleId])
  @@index([jewelryId])
}

model ReceiptSeries {
  id           String   @id @default(cuid())
  jewelryId    String
  name         String                       // "Punto de venta 1"
  type         ReceiptType
  direction    ReceiptDirection
  prefix       String   @default("")        // "A" | "B" | "C" | "X"
  pointOfSale  String   @default("0001")    // formato 4 dígitos
  nextNumber   Int      @default(1)         // incrementado atómicamente al emitir (ver 3.7)
  isActive     Boolean  @default(true)
  deletedAt    DateTime?
  createdAt    DateTime @default(now())
  updatedAt    DateTime @updatedAt

  jewelry  Jewelry   @relation(fields: [jewelryId], references: [id], onDelete: Cascade)
  receipts Receipt[]

  @@unique([jewelryId, type, prefix, pointOfSale])
  @@index([jewelryId])
}
```

### 3.7 Numeración atómica de ReceiptSeries

La asignación de número **debe ser atómica** para evitar:

- Dos comprobantes con el mismo número (pérdida de unicidad fiscal).
- Huecos en la secuencia por race conditions.

**Regla:** el incremento de `ReceiptSeries.nextNumber` y la creación del `Receipt` suceden **en la misma transacción de Prisma**. El patrón obligatorio es:

```ts
await prisma.$transaction(async (tx) => {
  // 1. Lock optimista sobre la fila de la serie (SELECT ... FOR UPDATE en Postgres
  //    se obtiene vía `update` sobre la PK — Prisma serializa la escritura).
  const series = await tx.receiptSeries.update({
    where: { id: seriesId },
    data:  { nextNumber: { increment: 1 } },
    select: { nextNumber: true, prefix: true, pointOfSale: true, type: true },
  });

  // 2. Construir el code con el número recién reservado (series.nextNumber - 1,
  //    porque increment: 1 deja ya apuntando al siguiente).
  const assigned = series.nextNumber - 1;
  const code = `${series.prefix}-${series.pointOfSale}-${String(assigned).padStart(8, "0")}`;

  // 3. Crear el Receipt con ese code. La unique (jewelryId, seriesId, code)
  //    da una segunda línea de defensa contra cualquier bug.
  const receipt = await tx.receipt.create({
    data: { code, seriesId, ...rest },
  });

  // 4. Resto de la cadena (lines, accountMovements) en la misma tx.
  return receipt;
});
```

**Qué NO hacer:**
- Leer `nextNumber`, incrementar en memoria y escribir en dos statements distintos.
- Usar `findFirst` + `update` separados.
- Reservar el número en una transacción y crear el Receipt en otra.

La regla se refuerza con el `@@unique([jewelryId, seriesId, code])` — si por cualquier bug dos transacciones obtienen el mismo número, la segunda falla con violación de unicidad y aborta.

**Recuperación ante fallo:** si la transacción aborta después del `update` (por ejemplo, falla la creación de líneas), Postgres hace rollback del `nextNumber` → el número queda libre para la próxima. No se generan huecos.

---

## 4. Capa 3 — Cuenta corriente (`CurrentAccountMovement`)

### 4.1 Modelo mental

La cuenta corriente por entidad (cliente o proveedor) es un **libro mayor** de movimientos ordenados por fecha. El saldo es la suma acumulada.

**REGLA ESTRICTA DE SIGNOS — fija para todas las contrapartes:**

- `DEBIT`  = **aumenta** la deuda que la contraparte tiene con la joyería.
- `CREDIT` = **reduce** la deuda que la contraparte tiene con la joyería.

Esta regla no cambia según sea cliente o proveedor. Lo que cambia es el signo del saldo:

- **Cliente** (la joyería vende): saldo positivo → el cliente debe; saldo negativo → hay crédito a favor del cliente.
- **Proveedor** (la joyería compra): saldo positivo → la joyería debe al proveedor; saldo negativo → pagos en exceso / crédito a favor de la joyería.

Tabla canónica de generación de movimientos:

| Evento | Entidad | Signo | Justificación |
|---|---|---|---|
| Factura emitida a cliente | cliente | `DEBIT` | sube la deuda del cliente |
| Nota de débito a cliente | cliente | `DEBIT` | suma deuda del cliente |
| Nota de crédito a cliente | cliente | `CREDIT` | reduce deuda del cliente |
| Cobro aplicado de cliente | cliente | `CREDIT` | reduce deuda del cliente |
| Factura recibida de proveedor | proveedor | `DEBIT` | sube la deuda que tenemos con el proveedor |
| Nota de crédito de proveedor | proveedor | `CREDIT` | reduce deuda nuestra con el proveedor |
| Nota de débito de proveedor | proveedor | `DEBIT` | suma deuda nuestra con el proveedor |
| Pago emitido al proveedor | proveedor | `CREDIT` | reduce deuda nuestra con el proveedor |

Saldo de la entidad en cualquier momento: `Σ DEBIT − Σ CREDIT` (en moneda base del tenant).

**Invariante:** todo movimiento proviene de un documento (receipt o payment allocation). No existen movimientos manuales. El saldo se reconstruye replicando los movimientos desde cero.

### 4.2 Orígenes válidos de un movimiento

Ver tabla canónica en **4.1 Modelo mental** más arriba. Todos los movimientos tienen exactamente uno de estos `source`:

- `RECEIPT` — el movimiento representa la emisión/recepción de un comprobante (factura, NC, ND). `receiptId` poblado.
- `PAYMENT_ALLOCATION` — el movimiento representa la aplicación (parcial o total) de un pago a un comprobante. `paymentAllocationId` poblado.

No existen otros orígenes. Cualquier intento de insertar un movimiento sin un `source` válido debe rechazarse en el nivel de servicio.

### 4.3 Shape sugerido

```prisma
enum AccountMovementKind {
  DEBIT
  CREDIT
}

enum AccountMovementSource {
  RECEIPT
  PAYMENT_ALLOCATION
}

model CurrentAccountMovement {
  id            String   @id @default(cuid())
  jewelryId     String
  entityId      String                          // CommercialEntity

  kind          AccountMovementKind             // DEBIT = aumenta deuda; CREDIT = reduce deuda
  source        AccountMovementSource

  // ── Referencias (exactamente una poblada según source) ──────────────────
  receiptId            String?                   // cuando source=RECEIPT
  paymentAllocationId  String?                   // cuando source=PAYMENT_ALLOCATION

  // ── Montos: doble guardado (moneda base + moneda original) ──────────────
  amountBase       Decimal @db.Decimal(14, 2)    // importe en moneda base del tenant
  amountOriginal   Decimal @db.Decimal(14, 2)    // importe en moneda del documento original

  // ── Snapshot de moneda (congelado al crear el movimiento) ───────────────
  // Se copia del Receipt o del Payment origen. Permite reconstruir el saldo
  // por moneda sin depender de FK que puedan cambiar.
  currencySnapshot   Json                        // { id, currencyCode, symbol, currencyRate, baseCurrencyCode, resolvedAt }
  currencyCode       String  @default("")
  currencyRate       Decimal @db.Decimal(18, 8)  // cotización usada para amountBase

  // ── Fechas ──────────────────────────────────────────────────────────────
  movementDate  DateTime                          // fecha del documento original (issueDate del Receipt, paymentDate del Payment)
  createdAt     DateTime @default(now())          // timestamp técnico del insert
  notes         String   @default("")

  jewelry Jewelry          @relation(fields: [jewelryId], references: [id], onDelete: Cascade)
  entity  CommercialEntity @relation(fields: [entityId], references: [id], onDelete: Restrict)
  receipt Receipt?         @relation(fields: [receiptId], references: [id], onDelete: Restrict)
  paymentAllocation PaymentAllocation? @relation(fields: [paymentAllocationId], references: [id], onDelete: Restrict)

  @@index([jewelryId, entityId, movementDate])
  @@index([receiptId])
  @@index([paymentAllocationId])
}
```

### 4.4 Reglas clave

- El saldo de una entidad = `Σ DEBIT − Σ CREDIT` (en moneda base).
- **Nunca** editar ni borrar movimientos. Errores se corrigen emitiendo otro comprobante.
- Vistas por moneda se reconstruyen agrupando por `currencyCode` — no se pierde la información original aunque el saldo total se muestre en base.
- Soft delete de entidad: los movimientos persisten (relación `onDelete: Restrict`).

---

## 5. Capa 4 — Pagos (`Payment` / `PaymentAllocation`)

### 5.1 Problema a resolver

Los modelos actuales (`SalePayment`, `PurchasePayment`) tienen:

- `SalePayment.saleId` obligatorio → un pago está atado a una venta específica. No permite aplicar un pago a dos facturas.
- `PurchasePayment.purchaseId` opcional (permite pago “a cuenta”) pero no hay tabla de alocación.

Para **pagos parciales** y **aplicación a múltiples comprobantes** necesitamos el patrón Payment + PaymentAllocation:

- `Payment` = el instrumento concreto (dinero que entra o sale: efectivo, tarjeta, transferencia, metal, etc.). Tiene monto total y componentes.
- `PaymentAllocation` = cómo ese monto se reparte entre comprobantes.

### 5.2 Convivencia con lo existente

No hay que migrar `SalePayment` / `PurchasePayment` de entrada: esos módulos están en preparación. El nuevo modelo los reemplaza cuando sales/purchases entren en profundidad. La convivencia se logra así:

- `Payment` es el nuevo modelo canónico. Va a reemplazar `SalePayment` y `PurchasePayment`.
- Mientras sales/purchases no usen `Payment`, se deja sin tocar.
- Cuando sales entre, el hook `onSaleConfirmed` empieza a crear `Payment` + `PaymentAllocation` y deja de usar `SalePayment`.

### 5.3 Shape sugerido

```prisma
enum PaymentDirection {
  INBOUND    // entra plata a la joyería (cobro a cliente)
  OUTBOUND   // sale plata de la joyería (pago a proveedor)
}

enum PaymentStatus {
  PENDING    // pre-confirmado (cheque a fecha, transferencia en proceso)
  CONFIRMED  // dinero acreditado, se suma al saldo
  VOIDED     // anulado (solo si no está alocado o se revierten alocaciones)
}

model Payment {
  id           String             @id @default(cuid())
  jewelryId    String
  entityId     String?                            // CommercialEntity (null = pago eventual / caja)

  direction    PaymentDirection
  status       PaymentStatus      @default(PENDING)

  // ── Monto total del pago ────────────────────────────────────────────────
  amountBase       Decimal @db.Decimal(14, 2)     // total en moneda base
  currencyCode     String  @default("")
  amountOriginal   Decimal @db.Decimal(14, 2)
  currencyRateToBase Decimal @db.Decimal(18, 8)

  // ── Fecha efectiva ──────────────────────────────────────────────────────
  paymentDate  DateTime
  confirmedAt  DateTime?
  voidedAt     DateTime?
  voidReason   String    @default("")
  notes        String    @default("")

  createdById  String?
  createdAt    DateTime  @default(now())
  updatedAt    DateTime  @updatedAt

  jewelry     Jewelry             @relation(fields: [jewelryId], references: [id], onDelete: Cascade)
  entity      CommercialEntity?   @relation(fields: [entityId], references: [id], onDelete: SetNull)
  components  PaymentComponent[]
  allocations PaymentAllocation[]

  @@index([jewelryId, entityId])
  @@index([jewelryId, status])
  @@index([paymentDate])
}

// Enum estricto para el instrumento del componente de pago.
// Este enum normaliza PaymentMethod.type y unifica la nomenclatura en toda
// la cadena de pagos (componentes + reportes + dashboards).
enum PaymentComponentType {
  CASH      // efectivo
  CARD      // tarjeta de crédito o débito (el distingo fino va en PaymentMethod.name)
  TRANSFER  // transferencia bancaria, SWIFT, PIX, CBU, alias, QR interoperable
  METAL    // pago en metal preciso (requiere metalVariantId + grams)
  CHECK    // cheque físico o electrónico (requiere reference + fecha de cobro)
  OTHER    // catch-all para casos que no encajen (ej: nota de crédito aplicada)
}

// Componentes del pago: uno por instrumento (permite mixto: efectivo + tarjeta + metal)
model PaymentComponent {
  id             String  @id @default(cuid())
  paymentId      String
  jewelryId      String

  paymentMethodId String?                         // FK a PaymentMethod (catálogo del tenant)
  methodName      String  @default("")            // snapshot del nombre al momento del pago
  componentType   PaymentComponentType            // enum estricto — ver arriba

  // ── Monto de este componente ────────────────────────────────────────────
  amount         Decimal @db.Decimal(14, 2)       // en la moneda del Payment

  // ── Para componentes METAL (obligatorios si componentType = METAL) ──────
  metalVariantId String?
  grams          Decimal? @db.Decimal(14, 6)
  gramsPure      Decimal? @db.Decimal(14, 6)

  // ── Para componentes CARD (opcionales) ──────────────────────────────────
  installments   Int      @default(1)
  surchargeAmount Decimal @default(0) @db.Decimal(14, 2)

  // ── Para componentes CHECK (opcionales) ─────────────────────────────────
  checkBank       String   @default("")
  checkDueDate    DateTime?

  reference      String   @default("")            // nro autorización, cheque, comprobante de transferencia
  createdAt      DateTime @default(now())

  payment        Payment         @relation(fields: [paymentId], references: [id], onDelete: Cascade)
  paymentMethod  PaymentMethod?  @relation(fields: [paymentMethodId], references: [id], onDelete: SetNull)
  metalVariant   MetalVariant?   @relation(fields: [metalVariantId], references: [id], onDelete: SetNull)

  @@index([paymentId])
  @@index([jewelryId])
  @@index([componentType])
}

// Aplicación de un Payment a comprobantes específicos.
// Un Payment puede alocarse a múltiples Receipt (parcial o total).
model PaymentAllocation {
  id          String   @id @default(cuid())
  jewelryId   String
  paymentId   String
  receiptId   String

  amountBase     Decimal @db.Decimal(14, 2)
  amountOriginal Decimal @db.Decimal(14, 2)

  // ── Snapshot de moneda (congelado al alocar) ───────────────────────────
  // Puede diferir del currencySnapshot del Payment si el Receipt está en otra
  // moneda — en ese caso, el currencyRate refleja la conversión al momento de
  // alocar (ej: Payment en USD alocado a Receipt en ARS usa la cotización del día).
  currencySnapshot   Json
  currencyCode       String  @default("")
  currencyRate       Decimal @db.Decimal(18, 8)

  appliedAt   DateTime @default(now())
  notes       String   @default("")

  payment    Payment                   @relation(fields: [paymentId], references: [id], onDelete: Cascade)
  receipt    Receipt                   @relation(fields: [receiptId], references: [id], onDelete: Restrict)
  movements  CurrentAccountMovement[]

  @@unique([paymentId, receiptId])        // un Payment aloca como máximo 1 vez a un mismo Receipt
  @@index([paymentId])
  @@index([receiptId])
  @@index([jewelryId])
}
```

### 5.4 Reglas de integridad — validaciones obligatorias

Toda creación de `PaymentAllocation` debe validar, **dentro de la misma transacción** que la inserta:

**R1 — No sobre-alocar el Payment:**
```
Σ PaymentAllocation.amountBase (para este paymentId, incluyendo la nueva)
  ≤ Payment.amountBase
```
Si se excede, la transacción aborta con error de negocio. Soft-check previo a nivel servicio + hard-check via índice parcial o constraint en migraciones futuras.

**R2 — No sobre-cobrar el Receipt (validación clave):**
```
Σ PaymentAllocation.amountBase (para este receiptId, convertido a la moneda del Receipt)
  ≤ Receipt.total  (en la moneda del Receipt)
```
**El saldo pendiente del comprobante es una invariante estricta.** Si una allocation pretende cubrir $120 de una factura que tiene saldo pendiente de $100, la transacción aborta. Esto previene:
- Pagos duplicados por error.
- Clientes que queden con saldo a favor no justificado.
- Inconsistencias en reportes de cartera.

**Cómputo del saldo pendiente** (regla de cálculo autorizada, vive en `src/lib/document-hooks/payment.hook.ts`):
```ts
async function getReceiptOutstanding(tx, receiptId): Promise<Decimal> {
  const receipt    = await tx.receipt.findUnique({ where: { id: receiptId } });
  const allocated  = await tx.paymentAllocation.aggregate({
    where:  { receiptId },
    _sum:   { amountOriginal: true },  // en la moneda del receipt
  });
  return receipt.total.minus(allocated._sum.amountOriginal ?? 0);
}
```

**R3 — Sin doble allocation al mismo Receipt:** el `@@unique([paymentId, receiptId])` lo garantiza a nivel DB.

**R4 — Coherencia de moneda:** `amountOriginal` debe estar en la moneda del `Receipt`, no del `Payment`. La conversión la resuelve el motor (`convertMoney` de `pricing-engine.currency.ts`).

**Estado de saldo del Receipt:** NO se persiste como columna. Se deriva siempre con `getReceiptOutstanding(...)` arriba. Fuente única de verdad = `Σ allocations`.

**Anulación:** anular un `Payment` en estado `CONFIRMED` requiere revertir sus allocations una por una, cada reversión genera un `CurrentAccountMovement` de signo opuesto. No se borran filas históricas.

---

## 6. Capa 5 — Hooks del sistema

Los hooks son el único canal autorizado para disparar la cadena comprobante → cuenta corriente → pago. Viven en `src/lib/document-hooks/` y son invocados desde `sales.service` y `purchases.service` cuando esos módulos se retomen.

### 6.0 Contrato transaccional (regla común a todos los hooks)

Todos los hooks **reciben** una `Prisma.TransactionClient` (`tx`) como primer parámetro y **nunca** abren su propia transacción. El caller (sales.service / purchases.service / payments.service) es el dueño de la transacción. Esto garantiza que:

> **Snapshot + Receipt + ReceiptLine + CurrentAccountMovement se crean en la misma transacción, o no se crea nada.**

Consecuencias concretas:

- Si la construcción del snapshot falla, el Receipt no se crea.
- Si la creación del Receipt falla, no hay CurrentAccountMovement huérfano.
- Si `ReceiptSeries.nextNumber` ya fue incrementado y algo posterior falla, Postgres hace rollback y el número queda libre.
- Un Payment y sus Allocations + CurrentAccountMovement reverso se crean juntos.

**Plantilla canónica para el caller:**

```ts
// En sales.service.ts (cuando se retome)
await prisma.$transaction(async (tx) => {
  await tx.sale.update({ where: { id: saleId }, data: { status: "CONFIRMED" } });

  const { receipts, accountMovements } = await onSaleConfirmed(tx, saleId, opts);

  // Si cualquier paso de onSaleConfirmed tira, Postgres revierte TODO.
  return { receipts, accountMovements };
});
```

**Prohibido:**
- Abrir transacciones anidadas dentro de un hook (`tx.$transaction(...)` — Prisma lo permite pero crea ambigüedad).
- Hacer escrituras “fuera” de la tx (ej: `prisma.x.create(...)` en lugar de `tx.x.create(...)`).
- Separar en dos transacciones el snapshot y el Receipt.

Todos los hooks están tipados para que aceptar `prisma` (cliente global) en vez de `tx` dé error de tipo, cerrando la puerta a uso incorrecto.

### 6.1 `onSaleConfirmed(tx, saleId, opts)`

```ts
// src/lib/document-hooks/sale.hook.ts
export async function onSaleConfirmed(
  tx: Prisma.TransactionClient,
  saleId: string,
  opts: {
    issueInvoice:       boolean;     // true = emite factura automáticamente
    issueDeliveryNote:  boolean;
    invoiceSeriesId?:   string;
    deliveryNoteSeriesId?: string;
  },
): Promise<{
  receipts:         Receipt[];
  accountMovements: CurrentAccountMovement[];
}>;
```

Pasos internos — **todos en la misma `tx`**:

1. Cargar `Sale` con líneas y entidades relacionadas.
2. Construir `DocumentPricingSnapshot` llamando al motor (`buildDocumentPricingSnapshot`). El snapshot NO se persiste suelto: se usa para poblar Receipt + ReceiptLine.
3. Para cada comprobante a emitir:
   a. Incrementar atómicamente `ReceiptSeries.nextNumber` (ver 3.7).
   b. Crear `Receipt` con `pricingSnapshot` + `currencySnapshot` + totales planos.
   c. Crear `ReceiptLine[]` con `pricingSnapshot` por línea + campos planos duplicados.
4. Para cada Receipt que afecta cuenta corriente (`INVOICE`, `DEBIT_NOTE`, `CREDIT_NOTE`): crear `CurrentAccountMovement` con signo según 4.1 y `currencySnapshot` copiado del Receipt.
5. Retornar `{ receipts, accountMovements }`.

**No** crea `Payment`: los cobros se registran separadamente vía `onPaymentApplied(...)`.

### 6.2 `onPurchaseConfirmed(tx, purchaseId, opts)`

Simétrico al anterior, con `ReceiptDirection=INBOUND`. La regla de signo de 4.1 ya define:

- Factura recibida de proveedor → `CurrentAccountMovement.kind = DEBIT` (aumenta deuda que tenemos con el proveedor).
- Nota de crédito recibida → `CREDIT` (reduce esa deuda).

### 6.3 `onReceiptVoided(tx, receiptId, reason)`

Para anular un comprobante:
- Cambia `Receipt.status` a `VOIDED` (solo permitido si no tiene `PaymentAllocation` activas — si las tiene, primero hay que anular los pagos).
- Genera `CurrentAccountMovement` de signo inverso por el monto original, en la misma `tx`.
- Copia el `currencySnapshot` original al movimiento reverso para mantener la coherencia de la cadena.
- **Nunca** borra filas.

### 6.4 `onPaymentApplied(tx, paymentId, allocations)`

Cuando se registra un cobro o pago:

1. Validar **R1** (no sobre-alocar el Payment) — ver 5.4.
2. Validar **R2** (no sobre-cobrar cada Receipt destino usando `getReceiptOutstanding`) — ver 5.4.
3. Crear `PaymentAllocation[]` en la misma `tx`.
4. Crear `CurrentAccountMovement[]` con signo opuesto al del comprobante original:
   - Si el receipt original generó `DEBIT`, la allocation genera `CREDIT` (reduce deuda de la contraparte).
   - Copiar el `currencySnapshot` correspondiente.
5. Actualizar `Payment.status = CONFIRMED` si aún no lo estaba.

Toda la secuencia en **una sola `tx`** — si alguna allocation falla, ninguna se persiste y no quedan movimientos huérfanos.

---

## 7. Flujo completo

Recorrido de un caso típico “cliente compra, factura a 30 días, paga parcial a los 15, paga resto a los 25”:

```
┌───────────────────────────────────────────────────────────────────────────┐
│ 1. Cliente pide cotización                                                │
│    Sale.status = DRAFT                                                    │
│    Frontend consume /pricing-preview (lectura del motor)                  │
│    NO hay Receipt aún                                                     │
└───────────────────────────────────────────────────────────────────────────┘
                                 ↓
┌───────────────────────────────────────────────────────────────────────────┐
│ 2. Vendedor confirma venta                                                │
│    sales.confirmSale(saleId) {                                            │
│       snapshot = buildDocumentPricingSnapshot(...)  ← pricing-engine      │
│       saleLines.update({ pricingSnapshot: snapshot.lines[i] })            │
│       sale.status = CONFIRMED                                             │
│       await onSaleConfirmed(tx, saleId, { issueInvoice: true })           │
│    }                                                                      │
│    onSaleConfirmed crea:                                                  │
│       · Receipt (INVOICE) con snapshot copiado                            │
│       · ReceiptLine[] con sus DocumentLineSnapshot                        │
│       · CurrentAccountMovement DEBIT por total                            │
└───────────────────────────────────────────────────────────────────────────┘
                                 ↓
┌───────────────────────────────────────────────────────────────────────────┐
│ 3. Cliente paga 50% a los 15 días                                         │
│    registerPayment({ entityId, amount: 500, components: [...] })          │
│    → crea Payment (status=CONFIRMED)                                      │
│    → el usuario aloca: PaymentAllocation({ paymentId, receiptId, 500 })   │
│    → onPaymentApplied genera CurrentAccountMovement CREDIT por 500        │
│    Saldo del cliente pasa de 1000 → 500 DEBIT                             │
└───────────────────────────────────────────────────────────────────────────┘
                                 ↓
┌───────────────────────────────────────────────────────────────────────────┐
│ 4. Cliente paga el resto                                                  │
│    registerPayment({ entityId, amount: 500 })                             │
│    → Payment + PaymentAllocation + CurrentAccountMovement CREDIT 500      │
│    Saldo del cliente: 0                                                   │
└───────────────────────────────────────────────────────────────────────────┘
                                 ↓
┌───────────────────────────────────────────────────────────────────────────┐
│ 5. Cliente devuelve 1 ítem (descuento post-venta)                         │
│    Usuario emite CREDIT_NOTE sobre el Receipt original                    │
│    → Nuevo Receipt (CREDIT_NOTE) con items/importes                       │
│    → CurrentAccountMovement CREDIT por monto de la NC                     │
│    Saldo del cliente pasa a -200 (a favor del cliente)                    │
│    La próxima factura puede compensar con este crédito vía allocation     │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## 8. Decisiones de diseño

### 8.1 Por qué `Receipt` ≠ `Sale`

Una venta es una **operación de negocio** (cliente compra, se descuenta stock, se computan comisiones). Un comprobante es un **documento fiscal** con vida propia (numeración, impuestos reportados, anulación regulada). Separarlos evita:

- Que cancelar una venta borre el historial fiscal.
- Que se pueda editar un documento emitido.
- Que una misma venta genere múltiples documentos (factura + remito + eventualmente NC) sin inflar el modelo de Sale.

### 8.2 Snapshot en cabecera **y** en línea

- Cabecera (`Receipt.pricingSnapshot`): trazabilidad completa para auditoría y reconstrucción.
- Línea (`ReceiptLine.pricingSnapshot`): permite queries line-level (ej: “qué ítems tuvieron margen negativo en el mes”) sin deserializar todo el JSON.

Redundancia controlada — el motor es el único que las construye, nunca divergen.

### 8.3 Cuenta corriente basada **solo** en documentos

- Cero movimientos manuales.
- El saldo se reconstruye 100% desde `Receipt` + `PaymentAllocation`.
- Auditable: toda fila tiene un `source` y un `receiptId` o `paymentAllocationId`.

### 8.4 Notas de crédito/débito como comprobantes nuevos

Alternativa descartada: modificar el receipt original. Descartada porque:
- Requiere “editar” un documento emitido.
- Pierde el historial de qué se corrigió y cuándo.
- Complica la auditoría contable.

### 8.5 `Payment` + `PaymentAllocation` vs `SalePayment`

`SalePayment` (actual) ata un cobro a una venta. Esto rompe casos reales:
- Cliente paga “a cuenta” sin referir factura.
- Un cobro cubre 3 facturas pendientes.
- Una transferencia se parte entre 2 ventas.

El patrón `Payment + PaymentAllocation` resuelve todo eso y es el estándar contable.

### 8.6 Moneda: doble guardado

Todos los montos persistidos en capas de comprobante/cuenta corriente/pago van en **dos formas**:
- `amountBase` (moneda base del tenant) — para agregaciones y reportes.
- `amountOriginal` + `currencyCode` + `currencyRateToBase` — para reconstrucción exacta en la moneda original del documento.

El motor ya expone `convertMoney` — se reusa.

### 8.7 No tocar `SalePayment` / `PurchasePayment` todavía

Esos modelos siguen vigentes mientras sales/purchases no se retomen a fondo. La migración a `Payment + PaymentAllocation` se hace cuando entre Fase 5 (sales/purchases profundo) y se ejecuta una migración de datos en ese momento. No hay presión ahora — TPTech está pre-producción.

### 8.8 ReceiptSeries separado

- Numeración por tipo + punto de venta evita colisiones y permite múltiples terminales facturando.
- Atómico bajo transacción (patrón ya usado en `ArticleMovement` para E-NNNN / S-NNNN).

### 8.9 Tipos de ítem en el snapshot

`DocumentLineSnapshot.itemKind` discrimina: `ARTICLE_SIMPLE | ARTICLE_VARIANT | SERVICE | COMBO`. En caso de COMBO se agrega `comboComponents[]` para conservar qué se vendió exactamente, incluso si después el combo cambia en maestro.

---

## 9. Qué **no** está en este diseño

Estos puntos quedan para Fase 5+ y se mencionan para que no sorprendan:

- **Retenciones y percepciones**: hoy están en `taxAmount` agregado. Si AFIP/similar exige desglose separado, se agrega al `taxSnapshot` sin tocar el resto.
- **Comprobantes electrónicos (AFIP)**: CAE, QR fiscal, código de barras. Requieren campos adicionales en `Receipt` pero son aditivos — no rompen el modelo.
- **Conversión de presupuesto a factura**: un `Receipt` de tipo QUOTE no afecta cuenta corriente; cuando el cliente acepta, se emite INVOICE que copia líneas del QUOTE vía snapshot. El QUOTE queda marcado como referenciado.
- **Multi-tenant facturación centralizada**: cada tenant tiene sus propias `ReceiptSeries`. Nada compartido.

---

## 10. Próximos pasos (Fase 5)

Cuando se decida avanzar a implementación:

1. Crear migración Prisma que agregue los 6 modelos nuevos (`Receipt`, `ReceiptLine`, `ReceiptSeries`, `CurrentAccountMovement`, `Payment`, `PaymentComponent`, `PaymentAllocation`) sin tocar los existentes.
2. Implementar `buildDocumentPricingSnapshot` en el pricing-engine.
3. Implementar `src/lib/document-hooks/` con `onSaleConfirmed` / `onPurchaseConfirmed` / `onReceiptVoided` / `onPaymentApplied`.
4. Implementar módulos CRUD de `receipts`, `payments`, `current-accounts` (lectura del libro mayor).
5. Migrar `SalePayment` / `PurchasePayment` a `Payment + PaymentAllocation` con script de datos.
6. Cablear `sales.service.confirmSale` y `purchases.service.confirmPurchase` a los hooks.
7. Agregar tests: inmutabilidad del snapshot, balance de cuenta corriente, sobre-alocación, doble pago.

Nada de lo anterior se hace en esta fase — este documento es el contrato arquitectónico.
