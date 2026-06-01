# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

---

# 🧠 Communication preferences

* Always respond in Spanish.
* The user is not a developer. Keep all explanations clear and simple.

---

# 🚨 PRINCIPIO GLOBAL (CRÍTICO)

👉 **“Si no sale del pricing-engine, está mal.”**

---

# 💰 Pricing / Totales (CRÍTICO ABSOLUTO)

## 📜 Documento vinculante: `src/lib/pricing-engine/POLICY.md`

`POLICY.md` es la **fuente de verdad conceptual** del motor comercial: rounding, snapshots, overrides, frontend lector puro, paridad simulador/factura/comparador, orden inmutable de capas y reproducibilidad histórica.

Reglas:

* Cualquier cambio de pricing (backend o frontend) debe **respetar** `POLICY.md`. Si no lo respeta, es bug.
* **No** se agregan cálculos comerciales nuevos en frontend sin antes actualizar `POLICY.md` y obtener aprobación.
* Si una pantalla nueva necesita una regla no contemplada, primero se actualiza `POLICY.md`, después se implementa.

## Fuente única de verdad

El único lugar donde se calculan:

* precios
* costos
* descuentos
* impuestos
* canal de venta
* cupones
* formas de pago
* redondeos
* márgenes
* totales de documentos
* snapshots

es:

👉 `src/lib/pricing-engine/`

El motor está partido por dominio (`pricing-engine.cost.ts`, `.cost-line-overrides.ts`, `.sale.ts`, `.pricelist.ts`, `.channel.ts`, `.coupon.ts`, `.payment.ts`, `.shipping.ts`, `.currency.ts`, `.balance.ts`, `.document.ts`). **Importar siempre desde el barrel `pricing-engine.ts`**, nunca un archivo interno.

Notas sobre los archivos menos obvios:

* `.types.ts` → tipos compartidos del motor (no contiene lógica).
* `.cost-line-overrides.ts` → resolución de overrides sobre líneas de costo (usado por snapshot v6).
* `.balance.ts` → arma el desglose metal/hechura (`buildBalanceBreakdownFromPrice`) usado en snapshots de balance.
* `.document.ts` → arma el snapshot completo de documentos (`buildDocumentPricingSnapshot`); es lo que consumen las hooks de confirmación.

Ver `src/lib/pricing-engine/README.md` para el contrato completo (orden de capas, reglas por tipo de ítem, snapshots).

## Whitelist — quién puede importar el motor

Solo estos módulos están autorizados a importar `pricing-engine`:

`articles`, `sales`, `purchases`, `cross-settlements`, `dashboard`, `article-groups`, `receipts`, y futuros módulos de pagos/cuenta corriente (lectura de snapshots).

Cualquier otro módulo que necesite un cálculo comercial debe pedirlo a uno de estos, **no** importar el motor por su cuenta.

---

## ❌ Prohibiciones

Está PROHIBIDO:

* Calcular precios en controllers
* Calcular precios en services (excepto orquestación)
* Calcular precios en helpers
* Calcular precios en frontend
* Usar valores del request como verdad
* Persistir totales sin recalcular desde el motor

---

## 📊 Regla crítica: totales de documentos

El backend/pricing-engine es la única fuente de verdad para:

* subtotal
* discountAmount
* taxAmount
* total
* redondeos
* margen
* snapshots

El frontend puede mostrar totales, pero nunca son autoridad.

Si el frontend envía:

* subtotal
* discountAmount
* taxAmount
* total

👉 el backend debe ignorarlos completamente y recalcular desde el pricing-engine.

👉 El backend puede loggear discrepancias, pero nunca confiar en esos valores.

---

## 🔄 Flujo de cálculo (orden obligatorio)

El orden SIEMPRE debe ser:

1. Costo
2. Lista de precios / precio manual
3. Promoción
4. Descuento por cantidad
5. Canal de venta
6. Cupón
7. Forma de pago
8. Impuestos
9. Redondeo
10. Totales
11. Snapshot

⚠️ Este orden NO puede alterarse.

---

## 🧾 Factura de venta / simulador

Reglas obligatorias:

* Simulador y Factura deben usar el mismo motor
* Preview y confirmación deben dar el mismo resultado
* Cualquier diferencia es un BUG

---

## 📸 Snapshots (CRÍTICO)

Al confirmar un documento:

* Se debe generar snapshot completo
* Se debe persistir snapshot en base de datos
* Nunca recalcular desde datos actuales

👉 Los documentos confirmados son inmutables

### Hooks de confirmación

Los efectos colaterales al confirmar un documento (emitir comprobante, mover cuenta corriente, etc.) viven en `src/lib/document-hooks/`. **Hoy solo existe `sale.hook.ts`** (`onSaleConfirmed`) que emite Receipt + ReceiptLine + CurrentAccountMovement junto con el snapshot. Los flujos de **purchase** y **cross-settlement** todavía no tienen hook propio — si necesitás efectos colaterales para esos, hay que crear el archivo equivalente (no asumir que existe).

Reglas:

* Las hooks reciben un `Prisma.TransactionClient` y **nunca abren su propia transacción** — se ejecutan dentro de la tx que abrió el service.
* Snapshot + comprobante + movimiento de cuenta corriente se crean en la **misma** tx, o no se crea nada.
* Si querés agregar efectos al confirmar venta/compra/etc., extendé el hook correspondiente; no los pongas en el service.
* Ver `src/modules/ARCHITECTURE-RECEIPTS-PAYMENTS.md` (§6.0) para el contrato transaccional.

---

## 🧩 Variantes

* Las variantes NO tienen precio propio
* Las variantes NO tienen costo propio
* Todo proviene del artículo padre

Único override permitido:

* peso (si aplica)

---

## 🧪 Testing obligatorio (pricing)

Todo cambio en pricing debe validar:

* preview vs confirmación
* simulador vs factura
* impuestos
* descuentos
* canal
* cupón
* redondeo

Si no hay test → no está terminado.

👉 **Test obligatorio de paridad**: cualquier cambio en `pricing-engine` debe tener (o actualizar) un test que compare el resultado del **preview** con el resultado de la **confirmación** sobre el mismo input. Si los dos resultados no son idénticos byte-a-byte (mismos totales, mismo snapshot), es un BUG.

---

## ⚠️ Antes de modificar pricing

Siempre:

1. Buscar si ya existe en pricing-engine
2. Identificar fuente de verdad
3. No crear lógica paralela
4. No duplicar funciones
5. Evaluar impacto en snapshot
6. Revisar tests existentes
7. Agregar tests si falta cobertura

---

# 🔄 REDONDEOS Y AJUSTES — CONTRATO CANÓNICO

> Detalle conceptual completo en el `CLAUDE.md` raíz (sección "Contrato canónico del modo DESGLOSADO" + "Redondeos y Ajuste Manual — Etapa A") y en `src/lib/pricing-engine/POLICY.md §R-Rounding-1/2/6/10/13/14`. Esta sección es la vista jerárquica que el backend implementa.

## Jerarquía (orden de aplicación, NO alterable)

| # | Mecanismo | Alcance | Vive en | Snapshot |
|---|---|---|---|---|
| 1 | **Redondeo Comercial** | **por línea** (precio de lista) | `pricing-engine.pricelist.ts` (capa pre-tax) | dentro de `priceListSnapshot` por línea |
| 2 | **Redondeo Financiero** | **por comprobante** (total final) | `pricing-engine.document.ts` + capa 16 (`document-physical-rounding-apply.ts`) | `Sale.documentRoundingSnapshot` |
| 3 | **Ajuste Manual** | **por comprobante** (intención humana) | `manual-adjustment/buildSnapshot.ts` (capa 17, POST-motor) | `Sale.manualAdjustmentSnapshot` |

## Modos soportados (cada mecanismo)

- **UNIFICADO** → opera sobre el total/línea sin distinguir metal/hechura.
- **DESGLOSADO** → opera en dos dominios DISJUNTOS:
  - **Metal padre** (físico en gramos) — Oro Fino, Plata, Platino, etc.
  - **Hechura / saldo monetario** (bucket único en pesos) — todo lo que NO es metal padre: hechura, productos, servicios, impuestos, descuentos, cupones, envíos, canal, forma de pago, redondeos monetarios, ajustes monetarios.

Para el Redondeo Financiero existe además **`documentRoundingMetalDomain`**:
- `PHYSICAL` → canónico (gramos → equivalente monetario). Capa 16 activa, redondeo monetario de metal suprimido (anti-doble).
- `MONETARY` → legacy (redondea $ del metal directo). Default histórico para back-compat.

Para el Ajuste Manual:
- `scope="UNIFIED"` → un único monto humano sobre `engineTotal`.
- `scope="BREAKDOWN"` → solo si `Sale.balanceMode === "BREAKDOWN"`. Acepta `metals[].targetGrams|deltaGrams` + `monetaryAmount` opcional. Si `scope=BREAKDOWN` con `balanceMode=UNIFIED` → **400 explícito**.

---

# ⚖️ REGLA FÍSICA DEL METAL (contrato obligatorio)

Todo redondeo o ajuste sobre un **metal padre** DEBE:

- modificar **gramos físicos** (`preGrams → postGrams`, `deltaGrams`);
- calcular `monetaryEquivalent = deltaGrams × metalPricePerGram` (cotización del balance);
- impactar `Sale.total` vía ese equivalente — NUNCA moverse al bucket monetario;
- quedar auditado en el snapshot del mecanismo con shape canónico:
  ```
  { metalParentId, metalParentName, preGrams, postGrams, deltaGrams,
    metalPricePerGram, monetaryEquivalent, mode?, direction?, fallback? }
  ```

## Prohibido

- ❌ Ajuste **monetario** sobre el metal sin contraparte física en gramos.
- ❌ Redondeo **monetario** sobre el metal sin contraparte física en gramos (salvo `documentRoundingMetalDomain="MONETARY"` legacy, que NO se extiende a mecanismos nuevos).
- ❌ Mover el equivalente monetario del metal al `breakdown.monetary.amount`.
- ❌ Sumar gramos y pesos en el mismo bucket persistido.

## Consolidación financiera (único punto de cruce)

```
totals.totalMonetaryAdjustment
  = totals.monetaryAdjustment       (bucket monetario directo)
  + totals.metalMonetaryEquivalent  (Σ equivalentes monetarios de los Δgramos)

Sale.total = max(0, engineTotal + totals.totalMonetaryAdjustment)
```

Los dos dominios solo se cruzan acá. Sumarlos en cualquier otra capa = bug.

---

# ➖ SALDOS NEGATIVOS — comportamiento confirmado

Auditoría 2026-05-29 (`document-balance-breakdown.test.ts §T58`, `pricing-engine.sale.ts:2692`):

## Qué está permitido (estado actual real)

- ✅ **`breakdown.monetary.amount` puede ser negativo** en modo BREAKDOWN. El clamp histórico `Math.max(0, ...)` se **removió** explícitamente. Caso de uso: cuando un descuento dirigido a hechura supera su subtotal, o cuando el ajuste manual sobre el bucket monetario es mayor en módulo que la hechura disponible.
- ✅ **Componentes negativos del pricing-engine** (hechura, metal, productos) son **válidos y deben preservarse** durante todo el flujo (preview → confirm → snapshot → display).
- ✅ **`deltaGrams` y `monetaryEquivalent` negativos** son válidos (redondeo PHYSICAL hacia abajo, ajuste manual con `targetGrams < preGrams`).

## Qué sí se clampa (única excepción)

- ⚠️ **`Sale.total` final del documento** se clampa a ≥0 (`pricing-engine.document.ts:1057,1073` + `pricing-engine.sale.ts:537`). Defensa para no emitir comprobantes con total negativo.
- Si el clamp recorta: **lo recortado es el ajuste del bucket monetario** (hechura/saldo). Los gramos del operador **se preservan** en el snapshot porque el ajuste físico pertenece al metal padre para siempre (principio "no mezclar").

## Regla obligatoria para nuevas capas

- Si agregás una capa que opera sobre componentes desglosados (totales por línea, breakdown por metal, ajustes nuevos): **NO agregar `Math.max(0, ...)`** sobre valores intermedios. Solo el total final del documento se clampa.
- Si un test "se rompe" porque un valor da negativo, primero verificar que el negativo no sea legítimo — el fix suele estar en cómo se lee, no en clampar.

---

# 🏛️ FACTURA DE VENTAS — PANTALLA MADRE (referencia)

> Detalle completo en `CLAUDE.md` raíz (sección "🏛️ Factura de Ventas — patrón madre oficial del sistema") y `tptech-frontend/CLAUDE.md` (sección "FACTURA DE VENTAS — PATRÓN MADRE").

## Implicancia para el backend

Toda mejora funcional cross-cutting (preview/confirm parity, snapshot v?, hooks, PDF, mail, audit log) **se implementa primero para Factura de Ventas**, se valida con sus tests de hardening, y solo después se replica a comprobantes hermanos (presupuestos, órdenes, NC, remitos, compras).

Antes de modificar módulos hermanos del comercial, el backend de Factura debe estar estabilizado:

1. `pricing-engine` con sus tests verdes.
2. `preview-confirm-parity.test.ts` verde.
3. `saleInvoicePdfProvider` + `pdf-parity.test.ts` verdes.
4. `tenantMailContext` + `DocumentEmailLog` con sus tests verdes.
5. Snapshots inmutables (manual + financial rounding) auditados.

Los SSOTs canónicos (`tenantMailContext.ts`, `saleInvoicePdfProvider.ts`, `document-email-log.ts`, `document-hooks/sale.hook.ts`) son la **referencia de implementación** para los comprobantes hermanos — clonar la estructura, no reinventarla. Ver "Patrón para documentos hermanos" arriba en este archivo.

---

# 🎯 OBJETIVO ACTUAL DEL PROYECTO

Prioridad absoluta (cierre de Factura de Ventas antes de avanzar masivamente sobre módulos hermanos):

1. **Estabilizar Pricing Engine** — capas inmutables, snapshot determinístico.
2. **Estabilizar Redondeos** — Comercial (por línea) + Financiero (por comprobante) + capa 16 PHYSICAL.
3. **Estabilizar Ajuste Manual** — UNIFIED + BREAKDOWN, con respeto al contrato físico del metal.
4. **Garantizar Preview = Confirmación** — `preview-confirm-parity.test.ts` byte-equivalente.
5. **Garantizar Simulador = Factura** — `simulator-vs-invoice-parity.test.ts` verde.
6. **Cerrar Factura de Ventas como pantalla madre** — SSOTs (mail, PDF, audit) verdes, hardening completo.

Recién después: replicar el patrón a presupuestos, órdenes, NC, remitos, compras. Cualquier feature nueva sobre módulos hermanos antes de cerrar Factura introduce divergencia que después cuesta más reconciliar.

---

# 📨 Mail — `tenantMailContext.ts` (SSOT)

Archivo: **`src/lib/tenantMailContext.ts`** — único módulo autorizado a leer la configuración de mail del `Jewelry` y componer los headers `From` + `Reply-To`. Todo flujo de envío (factura, futuros presupuesto / orden / NC / remito) debe pasar por este helper.

## Whitelist y patrón obligatorio

Cualquier `sendXxxByEmail(...)` en el backend hace:

```ts
import { resolveTenantMailContext } from "../../lib/tenantMailContext.js";

const mailCtx = await resolveTenantMailContext(jewelryId);
// → { from, replyTo, senderName, fromEmail, emailEnabled }

await sendMail({
  to, subject, html, text,
  from:    mailCtx.from,       // "<Joyería X> <no-reply@tptech.local>"
  replyTo: mailCtx.replyTo,    // emailReplyTo > email > undefined
  attachments: [{ ... }],
});
```

**Prohibido** leer `prisma.jewelry.findUnique({ select: { email: true }})` ad-hoc para resolver el Reply-To. Si aparece, es bug arquitectónico — usar el helper.

## Fallback chain (orden estricto)

| Header | Origen | Fallback si vacío |
|---|---|---|
| `From` display name | `Jewelry.emailSenderName` | sin display name (solo el email) |
| `From` email | `process.env.MAIL_FROM` | `undefined` → `mail.service` usa su default interno (`no-reply@tptech.local`) |
| `Reply-To` | `Jewelry.emailReplyTo` (dedicado) | `Jewelry.email` (legacy) → `undefined` (sin header) |

**Por qué `MAIL_FROM` es env y no per-tenant:** la dirección sender depende del dominio verificado en Postmark (responsabilidad de DevOps), no de cada joyería. La joyería solo configura el display name (`emailSenderName`) y el Reply-To (que apunta a su propia casilla).

## Funciones expuestas

- `resolveTenantMailContext(jewelryId): Promise<TenantMailContext>` — la lookup completa (1 query Prisma con `select` mínimo de 4 campos).
- `composeFromHeader(senderName, fromEmail): string | undefined` — helper PURO RFC 5322 (quotea display names con caracteres especiales, escape de comillas internas).
- `resolveReplyTo(emailReplyTo, legacyEmail): string | undefined` — helper PURO con fallback chain.

## Tests

`src/lib/__tests__/tenantMailContext.test.ts` (20 tests). Cubre composición de header (quoteado, escape, trim, nulls), fallback chain, query mínima (`select` exacto), tenant inexistente, `emailEnabled` propagado al caller.

---

# 📄 PDF — `saleInvoicePdfProvider.ts` (SSOT)

Archivo: **`src/lib/saleInvoicePdfProvider.ts`** — único punto de generación de PDFs de Factura. Descarga, impresión (a través del browser print), adjunto de mail y draft preview pasan por aquí.

## Whitelist y patrón obligatorio

| Caller backend | Función del provider | Endpoint expuesto |
|---|---|---|
| `sales.service.generateSalePdf(id, jewelryId)` | `renderFromPersisted({ sale, jewelryId })` | `GET /api/sales/:id/pdf` (descarga) |
| `sales.service.sendSaleByEmail(...)` | `renderFromPersisted({ sale, jewelryId })` | `POST /api/sales/:id/send-email` (mail) |
| `sales.draft-pdf.service.renderSaleDraftPdf(input)` | `renderFromDraft({ printable, page, filename })` | `POST /api/sales/render-pdf` (descarga draft) |
| `sales.draft-pdf.service.sendSaleDraftByEmail(...)` | `renderFromDraft({ printable, page, filename })` | `POST /api/sales/send-draft-email` (mail draft) |

**Prohibido** importar `renderInvoicePdf`, `renderInvoicePdfFromHtml` o `renderPrintableToPdf` directo desde un service. Solo el provider los conoce.

## Responsabilidades del provider

1. **Adapter `Sale → PdfSale`** — convierte Decimals/strings a números planos. **Cero matemática** (toN solo serializa).
2. **Engine selector** — `PDF_ENGINE=html` (default, Puppeteer) o `PDF_ENGINE=pdfkit`. Si HTML falla, fallback transparente a pdfkit.
3. **Filename composer (`composeFilename`)** — `Borrador-<saleCode>.pdf` / `Factura-ANULADA-<num>.pdf` / `Factura-<num>.pdf`.
4. **Draft wrapper** — para `renderFromDraft` delega a `renderPrintableToPdf` (mismo componente shared que el browser print).

## Shape uniforme del resultado

```ts
{
  buffer:   Buffer;
  filename: string;
  mimeType: "application/pdf";
  source:   "persisted" | "draft";
}
```

Descarga y mail comparten el **mismo buffer por referencia** (no es una copia) → byte-equivalencia garantizada arquitectónicamente.

## Plantilla activa

El provider llama `getOrCreateTemplate(jewelryId, "FACTURA")` y pasa el `DocumentTemplate` al renderer. **NUNCA** hardcodea logo, columnas visibles, márgenes, footer, términos, moneda — todo viene del template. Si el aspecto visual del PDF "se ve raro", el fix va en `DocumentTemplate` (configuración) o en `SaleInvoicePrintable` (shared), **nunca** en el provider o en el renderer.

## Tests

- `src/lib/__tests__/saleInvoicePdfProvider.test.ts` (20 tests). Shape uniforme, plantilla activa, multi-tenant, filename adaptive por status, determinismo, ausencia de matemática comercial.
- `src/modules/sales/__tests__/pdf-parity.test.ts` (14 tests). Paridad de los 4 call-sites: misma función del provider, mismos argumentos, mismo buffer propagado al consumer.
- Guards no-math: `renderInvoicePdf.no-math.guard.test.ts` + `renderInvoicePdfFromHtml.no-math.guard.test.ts` — bloquean reintroducir cálculos comerciales en los renderers.

---

# 📑 DocumentEmailLog — audit inmutable

Modelo Prisma `DocumentEmailLog` + helper `src/lib/document-email-log.ts` (`createDocumentEmailLog`).

**Toda llamada a `sendMail(...)` para un documento DEBE persistir un log** — éxito o falla. El helper `createDocumentEmailLog` **traga errores internamente** (si la DB falla, el envío no se rompe).

Campos clave:
- `documentKind`: `"SALE_INVOICE"` hoy. Futuros: `"QUOTE"`, `"ORDER"`, `"CREDIT_NOTE"`, `"DELIVERY_NOTE"`.
- `documentId`: STRING sin FK (sobrevive soft-delete del documento).
- `saleId` / `purchaseId` / etc.: FK opcional para joins eficientes desde la UI de historial.
- `providerMessageId`: del provider en producción (Postmark `MessageID`), `null` en preview/console.
- `status`: `"SENT"` | `"FAILED"`.
- `subjectSnapshot` / `bodySnapshot` (TEXT, plano) / `attachmentFilename`: snapshot inmutable.

Sin endpoint de update — el log es de auditoría pura.

---

# 🛠️ Patrón para documentos hermanos (presupuestos / órdenes / NC / remitos)

Cuando se sume un comprobante nuevo, replicar la estructura de Factura siguiendo este molde:

## Backend (orden de implementación)

1. **Modelo Prisma** del documento (`Quote`, `Order`, `CreditNote`, `DeliveryNote`) con `jewelryId` + `deletedAt` + snapshots.
2. **Módulo** `src/modules/<comprobante>/` con `routes / controller / service / schemas`.
3. **Whitelist del pricing-engine** — agregar el módulo a la lista de importadores autorizados (sección "Whitelist" arriba en este archivo).
4. **Endpoint de preview** `POST /api/<comprobante>/preview` — usa `pricing-engine` con el orden de capas obligatorio.
5. **Hook de confirmación** en `src/lib/document-hooks/<comprobante>.hook.ts` si tiene efectos colaterales (movimientos de cuenta corriente, stock, etc.). Mismo contrato transaccional que `sale.hook.ts`.
6. **PDF provider** `src/lib/<comprobante>PdfProvider.ts`:
   - Misma firma del SSOT: `renderFromPersisted({ <doc>, jewelryId })` + `renderFromDraft({ printable, page, filename })` → `{ buffer, filename, mimeType, source }`.
   - Usa `getOrCreateTemplate(jewelryId, "<COMPROBANTE>")` con el `kind` nuevo.
   - Adapter `<Doc> → Pdf<Doc>` análogo al de Factura.
   - Helper `composeFilename` propio del comprobante.
7. **Mail** — reutilizar `sendMail` + `resolveTenantMailContext(jewelryId)` + `createDocumentEmailLog({ documentKind: "<COMPROBANTE>", ... })`. **NO crear** otro provider de mail.
8. **DocumentTemplate** — agregar el nuevo `kind` al enum/seed con defaults razonables. La UI de configuración (Configuración → Documentos) ya soporta cualquier kind.

## Frontend (orden de implementación)

1. **Preview payload builder**: `tptech-frontend/src/lib/<comprobante>/build<Comprobante>PreviewPayload.ts` (no envía subtotal/total/discount/tax).
2. **Preview hidrator**: `apply<Comprobante>PreviewToDraft.ts` (passthrough puro, cero matemática).
3. **Hook**: usar `usePreviewFlow` tal cual (es genérico).
4. **Pantalla**: clonar la estructura de `VentasFacturas.tsx` (estado local, integración con preview, layout V2 si corresponde).
5. **Printable**: agregar `<XxxPrintable>` a `tptech-shared/document-printables/` siguiendo el shape del existente.
6. **Sacar la pantalla** del whitelist de POC de `no-frontend-document-math.guard.test.ts` (si estaba ahí). Si la pantalla compila sin el whitelist, hizo el patrón bien.

## Tests obligatorios del comprobante nuevo

- `<comprobante>PdfProvider.test.ts` — shape uniforme, plantilla activa, multi-tenant, filename adaptive, determinismo. Molde: `saleInvoicePdfProvider.test.ts` (20 tests).
- `preview-confirm-parity.test.ts` — paridad byte a byte entre `POST /preview` y `POST /confirm`. Molde: `sales/__tests__/preview-confirm-parity.test.ts`.
- `pdf-parity.test.ts` extendido — agregar los 4 call-sites del nuevo comprobante (descarga / mail / draft / mail draft).
- `send-email.test.ts` análogo — sender del tenant, Reply-To, DocumentEmailLog persistido.

---

# 📦 Stock — segunda fuente de verdad

Análogo al pricing-engine, **toda la lógica de stock pasa por `src/lib/stock-engine.ts`**. Es el único lugar autorizado a escribir en `ArticleStock`.

Reglas clave (ver el comentario de cabecera del archivo para el detalle completo):

* `ArticleMovement` + `ArticleMovementLine` = fuente de verdad histórica. `ArticleStock` es solo cache materializado.
* Los movimientos son **inmutables** una vez `CONFIRMED`. Para revertir → estado `VOIDED` (no hay endpoint de edit ni de delete).
* Solo movimientos con `sourceType=MANUAL` se pueden anular desde el módulo de movimientos. Los de SALE / PURCHASE / IMPORT se anulan desde su módulo de origen.
* `articleType=SERVICE` no tiene stock; solo `stockMode=BY_ARTICLE` genera saldo.
* Variantes: si el artículo tiene variantes activas, el stock vive **solo** en variantes (`variantId ≠ null`). Sin variantes activas → solo en el padre (`variantId = null`).
* Saldo negativo está permitido (se registra pero no se bloquea).
* Toda operación de stock debe correr dentro de una transacción Prisma.

👉 Si ves escritura a `ArticleStock` fuera de `stock-engine.ts`, es un bug.

---

# 👤 UserPreference — preferencias personales por usuario

## Arquitectura

`UserPreference` ≠ favorito global. Son dos conceptos distintos que **no se
mezclan**:

- **`UserPreference`** → preferencias **personales por usuario**. Modelo Prisma
  scopeado (`@@unique([userId, scope])`). Solo **precarga UI**; nunca afecta
  cálculos. Dueño del dominio: `src/modules/user-preferences/`
  (`GET`/`PUT /api/user-preferences/me`).
- **`isFavorite`** → favorito **global de la joyería** (compartido por todos
  los usuarios del tenant): listas de precios, canales, vendedores, medios de
  pago, envíos.

### Scope actual

- `SALES_INVOICE` (único valor del enum `UserPreferenceScope` hoy). El modelo
  está pensado para crecer a otros documentos sin cambios estructurales.

### Campos implementados

`defaultWarehouseId`, `defaultSellerId`, `defaultPriceListId`,
`defaultChannelId`, `defaultCurrencyId` (todos opcionales).

### Prioridad de resolución de defaults (orden obligatorio)

1. Default comercial del cliente/proveedor (si aplica)
2. `UserPreference` del usuario
3. Favorito de la joyería (`isFavorite`)
4. Primer activo disponible

### Reglas importantes

- **Almacenes** = preferencia **personal** (`UserPreference.defaultWarehouseId`).
  La estrella de Inventario → Almacenes escribe `UserPreference` vía
  `user-preferences.service.ts` (`setSalesDefaultWarehouseId`), nunca el legacy.
- **Listas / canales / vendedores / pagos / envíos** = favoritos **globales**
  (`isFavorite`).
- `User.favoriteWarehouseId` es **legacy**: solo lectura como fallback
  transitorio (`getSalesDefaultWarehouseId`). **No escribir** ese campo en
  flujos nuevos. No se borró todavía (cleanup futuro).
- `validateOwnership` garantiza que cada default pertenezca al `jewelryId` del
  usuario (modelo sin relaciones Prisma a propósito; integridad en el service).
- Moneda: se guarda `currencyId`; el frontend mapea `currencyId → currencyCode`
  y resuelve `latestRate` vigente del catálogo (Divisas). La factura usa code.
- `pricing-engine` sigue siendo la única fuente de verdad de pricing.
  `UserPreference` no recalcula nada.

## ❌ No hacer

- ❌ Mezclar favoritos globales (`isFavorite`) con `UserPreference`.
- ❌ Guardar preferencias de UI dentro del modelo `User`.
- ❌ Escribir `User.favoriteWarehouseId` (legacy solo lectura).
- ❌ Hardcodear `ARS` ni `fxRate=1` salvo que la moneda sea la base real.
- ❌ Duplicar la lógica de resolución de defaults o crear flujos paralelos de
  favoritos. La whitelist de quién importa el motor de pricing **no** incluye
  `user-preferences` (solo precarga UI).

---

# 📱 Performance para dispositivos móviles (OBLIGATORIO)

La app es usada desde celulares con conexión limitada. Las respuestas de la API deben ser lo más livianas posible:

* Paginación obligatoria (`skip` / `take`)
* Usar `select` en Prisma
* Evitar N+1 queries
* No enviar campos innecesarios
* JSON liviano
* Compresión activa en producción

---

# 🚀 Deployment

* Hosting: Render
* Backend: Web Service
* Frontend: Static Site
* Repositorios: GitHub

Email:

* Postmark en producción (`MAIL_MODE=production`)
* En dev/staging hay route de **preview de mails** (registrada por `registerMailPreviewRoute` desde `src/lib/mail.service.ts`) — útil para inspeccionar plantillas sin enviarlas.

Storage:

* Cloudflare R2 (fallback local)

---

# 🔧 Variables de entorno (mínimas)

Para arrancar el backend en local:

* `DATABASE_URL` → Postgres (ej: `postgresql://user:pass@host:5432/db`)
* `JWT_SECRET` → mínimo 10 caracteres
* `PORT` → opcional, default `3001`
* `MAIL_MODE` → `production` activa Postmark; cualquier otro valor habilita preview de mails
* `POSTMARK_TOKEN` → solo si `MAIL_MODE=production`
* R2 (opcional, si falta cae a `/uploads` local): `R2_ACCOUNT_ID`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, `R2_BUCKET`, `R2_PUBLIC_URL`

Todo lo demás tiene defaults razonables. En producción (Render) se setea desde el dashboard.

---

# ⚙️ Commands

```bash
# Server
npm run dev                  # tsx watch — dev en puerto 3001
npm run build                # prisma generate + tsc
npm run start                # prisma migrate deploy + node dist/index.js (producción)
npm run seed                 # tsx prisma/seed.ts (no correr salvo pedido explícito)

# Prisma
npm run prisma:generate      # SIEMPRE después de tocar schema.prisma
npm run prisma:migrate:dev   # crea + aplica migración local
npm run prisma:migrate:deploy

# Tests (Vitest)
npm test                     # corre vitest run (toda la suite una sola vez, NO modo watch)
npm run test:watch           # vitest en modo watch interactivo
npm run test:coverage
npx vitest run <archivo>     # un único archivo (ej: src/lib/pricing-engine/__tests__/sale.test.ts)
npx vitest run <archivo> -t "<nombre>"   # un único test por nombre dentro del archivo
npx vitest run -t "<patron>"             # busca tests por nombre en toda la suite (útil si no recordás el archivo)
npx vitest run <archivo> --coverage      # coverage de un único archivo

# TypeScript
npx tsc --noEmit             # chequeo rápido de tipos sin compilar a dist/

# Scripts de migración / debug (one-shot)
npm run migrate:cost-to-lines   # migra costos legacy a ArticleCostLine
npm run check:legacy-cost       # diagnostica artículos con costo legacy
npm run debug:entity-discount   # diagnostica descuentos por entidad comercial
```

Los tests viven co-locados en carpetas `__tests__/`:

* `src/lib/__tests__/` — utilidades comunes
* `src/lib/pricing-engine/__tests__/` — motor de precios
* `src/lib/document-hooks/__tests__/` — hooks de documentos
* `src/modules/<modulo>/__tests__/` — por módulo

## Tests del pricing-engine

El motor tiene **más de 30 tests** en `src/lib/pricing-engine/__tests__/`. Para ver el listado actualizado, leer ese directorio directamente — no se enumera acá para evitar que la doc quede desactualizada.

Tests clave para orientarse (ejemplos representativos):

* `cost.test.ts` — cálculo de costo desde ArticleCostLine
* `sale.test.ts` — motor de venta (resolveFinalSalePrice y capas)
* `metal-hechura.test.ts` — desglose metal/hechura
* `integration.test.ts` — flujo end-to-end del motor
* `simulator-vs-invoice-parity.test.ts` — paridad simulador ↔ factura
* `endpoint-parity.test.ts` — paridad entre endpoints que consumen el motor
* `document-totals.test.ts` / `document-breakdown.test.ts` — totales y breakdown por línea de documento confirmado
* `cross-flow-consistency.test.ts` — consistencia entre flujos (venta, compra, cross-settlement)

Tests de paridad fuera del motor:

* `src/modules/sales/__tests__/preview-confirm-parity.test.ts` — paridad entre preview de venta y confirmación final (vive en el módulo `sales`).

⚠️ Tras editar `prisma/schema.prisma`: correr `prisma:generate` y reiniciar `npm run dev` a mano (tsx watch no recarga `node_modules/@prisma/client`).

---

# 🔐 Multi-tenancy (CRÍTICO)

* Todo está scopeado por `jewelryId`
* Nunca confiar en el cliente
* Siempre usar `req.tenantId` / `req.user.jewelryId`

---

# 🔑 Auth

* JWT en cookie httpOnly `tptech_session`
* Bearer token como fallback
* `requireAuth`:

  * valida usuario
  * valida estado
  * calcula permisos
  * setea contexto

---

# 🧾 Soft delete

* Usar `deletedAt`
* Nunca hard delete en entidades críticas

---

# 📦 Uploads

* R2 si está configurado
* sino `/uploads` local

---

# 🪵 Logs

* No usar `console.log` salvo en scripts one-shot. El middleware `perfLogger` (`src/middlewares/perfLogger.ts`) ya emite una línea por request con método, URL, status, duración y `tenant`/`user` cuando corresponde. En producción solo loggea requests lentos (≥ `slowMs`, default 700ms); en dev loggea todo.
* `requestContextMiddleware` (`src/lib/prisma.ts`) asigna un `reqId` por request vía `AsyncLocalStorage`. Usarlo para correlacionar logs si agregás logging propio.

---

# ⚠️ Error handling

```ts
const err: any = new Error("Mensaje");
err.status = 400;
throw err;
```

---

# 🧱 Convenciones de módulos

Cada módulo en `src/modules/<nombre>/` se compone de:

* `<nombre>.routes.ts` → routing + `requireAuth` + `asyncHandler`
* `<nombre>.controller.ts` → request/response, delega al service (sin lógica)
* `<nombre>.service.ts` → lógica + queries Prisma
* `<nombre>.schemas.ts` → validación con Zod

Reglas obligatorias:

* **ESM puro** (`"type": "module"`): los imports relativos a `.ts` deben terminar en `.js`. Ej: `import { foo } from "./foo.js"`.
* Toda query Prisma con `select` explícito (no `findMany` pelado) — ver sección de performance móvil.
* Toda query filtra `deletedAt: null` y `jewelryId` del contexto del request.
* Soft delete: `{ deletedAt: new Date(), isActive: false }`.
* Validación de invariantes: `assert(cond, "msg")` lanza `{ status: 400 }`.
* Uploads: `multer.memoryStorage()` + `uploadFile()` de `src/lib/r2.ts` + `buildObjectKey()` de `src/lib/storage/keys.ts`.

## Registrar un módulo nuevo

Todo módulo nuevo debe:

1. Vivir en `src/modules/<nombre>/` con la estructura de arriba.
2. Exportar un `Router` por default desde `<nombre>.routes.ts`.
3. **Quedar registrado en `src/routes/index.ts`** con `requireAuth` salvo que sea explícitamente público (auth, webhooks).

> No hay generador de scaffolding. Para crear un módulo nuevo, **copiar la estructura de un módulo simple** como `taxes` o `payments` (routes + controller + service + schemas) y renombrar.

---

# 🗺️ Mapa de dominios

`src/modules/` agrupa ~36 módulos. Para orientarse rápido:

| Dominio | Módulos |
|---|---|
| Auth & accesos | `auth`, `users`, `roles`, `permissions` |
| Catálogo | `articles`, `article-groups`, `article-movements`, `categories`, `attribute-defs`, `units`, `import-batches`, `valuation`, `catalogs` |
| Comercial | `sales`, `purchases`, `cross-settlements`, `receipts`, `commercial-entities`, `sales-channels`, `coupons`, `promotions`, `quantity-discounts`, `price-lists` |
| Configuración | `taxes`, `payments`, `shipping`, `sellers`, `warehouses`, `company`, `printer-profiles`, `label-templates`, `document-templates` |
| Soporte | `dashboard`, `movimientos`, `storage` |

Toda la API se monta bajo `/api/<modulo>` desde `src/routes/index.ts`.

---

# 🛠️ Infra clave

* **Entrypoint del servidor**: `src/index.ts` (carga `dotenv`) → `src/server.ts` (escucha el puerto) → `src/app.ts` (construye el `app` Express: helmet, CORS con credenciales, parsers JSON/urlencoded de 1mb, `cookieParser`, `requestContextMiddleware`, `perfLogger`, rate limit global, montaje de `/api`, error handler).
* Toda la API se monta bajo el prefijo `/api` (ver `src/app.ts`). El frontend usa `VITE_API_URL` apuntando a esa base.
* **Health checks**: `GET /api/health` devuelve `{ ok: true, service: "tptech-backend" }`; `GET /` devuelve `"TPTech Backend OK 🚀"`. Útiles para chequear el deploy en Render.
* **Mail preview en dev/staging**: si `MAIL_MODE !== "production"`, `registerMailPreviewRoute(app)` agrega una ruta para previsualizar los mails generados.
* **Uploads estáticos**: la carpeta `uploads/` se sirve tanto en `/uploads` (directo backend) como en `/api/uploads` (proxy Vite).
* `src/lib/prisma.ts` define `requestContextMiddleware` con `AsyncLocalStorage`: asigna un `reqId` por request (lee `x-request-id` / `x-correlation-id` o genera uno). Útil para logging y trazabilidad.
* Prisma 7 — la conexión usa **`PrismaPg` adapter** explícito (`new PrismaClient({ adapter })`). Antes de tocar `src/lib/prisma.ts` o agregar otra conexión, tener presente que Prisma 7 ya no admite el modo legacy sin adapter.
* Migraciones con descripción:

  ```bash
  npm run prisma:migrate:dev -- --name <descripcion_corta>
  ```

---

# 🧭 Regla final

👉 Si ves lógica de precios fuera de `pricing-engine`, es un error.

👉 Si frontend y backend no coinciden, el problema está en la arquitectura, no en la UI.

---
