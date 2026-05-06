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

El motor está partido por dominio (`pricing-engine.cost.ts`, `.sale.ts`, `.pricelist.ts`, `.channel.ts`, `.coupon.ts`, `.payment.ts`, `.currency.ts`, `.balance.ts`, `.document.ts`). **Importar siempre desde el barrel `pricing-engine.ts`**, nunca un archivo interno.

Notas sobre los archivos menos obvios:

* `.balance.ts` → arma el desglose metal/hechura (`buildBalanceBreakdownFromPrice`) usado en snapshots de balance.
* `.document.ts` → arma el snapshot completo de documentos (`buildDocumentPricingSnapshot`); es lo que consumen las hooks de confirmación.

Ver `src/lib/pricing-engine/README.md` para el contrato completo (orden de capas, reglas por tipo de ítem, snapshots).

## Whitelist — quién puede importar el motor

Solo estos módulos están autorizados a importar `pricing-engine`:

`articles`, `sales`, `purchases`, `cross-settlements`, `dashboard`, `article-groups`, y futuros módulos de comprobantes/pagos/cuenta corriente (lectura de snapshots).

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

Los efectos colaterales al confirmar un documento (emitir comprobante, mover cuenta corriente, etc.) viven en `src/lib/document-hooks/`. Hoy existe `sale.hook.ts` (`onSaleConfirmed`) que emite Receipt + ReceiptLine + CurrentAccountMovement junto con el snapshot.

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
npm test                     # corre toda la suite una vez
npm run test:watch
npm run test:coverage
npx vitest run <archivo>     # un único archivo (ej: src/lib/pricing-engine/__tests__/sale.test.ts)
npx vitest run <archivo> -t "<nombre>"   # un único test por nombre dentro del archivo
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

Cobertura por archivo (en `src/lib/pricing-engine/__tests__/`):

* `cost.test.ts` — cálculo de costo desde ArticleCostLine
* `sale.test.ts` — motor de venta (resolveFinalSalePrice y capas)
* `metal-hechura.test.ts` — desglose metal/hechura
* `integration.test.ts` — flujo end-to-end del motor
* `simulator-vs-invoice-parity.test.ts` — paridad simulador ↔ factura
* `endpoint-parity.test.ts` — paridad entre endpoints que consumen el motor
* `document-totals.test.ts` — totales de documentos confirmados
* `document-breakdown.test.ts` — breakdown por línea de documento
* `cross-flow-consistency.test.ts` — consistencia entre flujos (venta, compra, cross-settlement)
* `src/modules/sales/__tests__/preview-confirm-parity.test.ts` — paridad entre preview de venta y confirmación final (vive en el módulo `sales`, no en `pricing-engine`)

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

`src/modules/` agrupa ~40 módulos. Para orientarse rápido:

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
