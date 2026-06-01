// src/modules/user-preferences/user-preferences.service.ts
//
// Preferencias por usuario, scopeadas por contexto (`scope`).
// Fase 1: solo SALES_INVOICE (precarga de la Factura de ventas).
//
// Reglas:
//  - Solo precarga campos de UI. NUNCA toca pricing-engine ni cálculos.
//  - Todos los defaults deben pertenecer al mismo jewelryId del usuario
//    (se valida acá, porque el modelo no tiene relaciones Prisma).
//  - Una sola fila por (userId, scope) → upsert.
import { prisma } from "../../lib/prisma.js";
import { Prisma, type UserPreferenceScope } from "@prisma/client";

const SCOPE: UserPreferenceScope = "SALES_INVOICE";

function assert(cond: any, msg: string): asserts cond {
  if (!cond) {
    const err: any = new Error(msg);
    err.status = 400;
    throw err;
  }
}

function s(v: any): string {
  return String(v ?? "").trim();
}

/** null si viene vacío/ausente; string trim si viene con valor. */
function optId(v: any): string | null {
  if (v === null || v === undefined) return null;
  const t = s(v);
  return t.length ? t : null;
}

export type GlobalDiscountType = "PERCENT" | "AMOUNT";

/** Shape MÍNIMO del layout config. El backend NO valida ids ni widths —
 *  solo persiste el JSON. El frontend valida con `reconcileLayout`. */
export type InvoiceLayoutConfig = {
  version: number;
  cards: unknown[];
  [k: string]: unknown;
};

/** Plantillas de vista predefinidas para la Factura de ventas.
 *  Valores cerrados — cualquier string ajeno se sanitiza a `null` en el
 *  upsert (igual que `defaultGlobalDiscountType`). El frontend resuelve
 *  cada preset a un objeto de configuración visual. Cero impacto en
 *  pricing-engine.
 *
 *  Default frontend: "COMPACT" (vista moderna optimizada — antes
 *  "BALANCED"). La compatibilidad con DB legacy se maneja en el
 *  sanitizador `optInvoiceViewPreset`: si en DB hay "BALANCED" persistido,
 *  se mapea a "COMPACT" sin requerir migration de datos. */
export type InvoiceViewPreset = "COMPACT" | "CLASSIC" | "ONE_LINE";
// Valores aceptados por el sanitizador. Los legacy ("SINGLE_COLUMN",
// "CUSTOM", "BALANCED", "FINANCIAL") se mapean en `optInvoiceViewPreset`
// al enum oficial antes de persistir; aca solo listamos los que pasan
// derecho como `InvoiceViewPreset`.
const VALID_INVOICE_VIEW_PRESETS: ReadonlyArray<InvoiceViewPreset> = [
  "COMPACT", "CLASSIC", "ONE_LINE",
];

/** Configuraciones finas de UI del modal de Factura (UX.20). Tipo OPACO
 *  desde el backend — solo persiste/devuelve el JSON tal cual. La
 *  validación de keys/valores vive en el frontend
 *  (`resolveInvoiceUiPreferences`). Forma esperada hoy:
 *    { density: "COMPACT"|"NORMAL"|"COMFORTABLE", stickyActions: boolean,
 *      ...futuros toggles } */
export type InvoiceUiPreferences = {
  [k: string]: unknown;
};

export type SalesPreferenceDTO = {
  scope: UserPreferenceScope;
  defaultWarehouseId: string | null;
  defaultSellerId: string | null;
  defaultPriceListId: string | null;
  defaultChannelId: string | null;
  defaultCurrencyId: string | null;
  defaultGlobalDiscountType: GlobalDiscountType | null;
  invoiceLayoutConfig: InvoiceLayoutConfig | null;
  preferredInvoiceViewPreset: InvoiceViewPreset | null;
  invoiceUiPreferences: InvoiceUiPreferences | null;
};

/** Sanitiza el tipo del descuento global. Acepta solo "PERCENT" | "AMOUNT".
 *  Cualquier otro string se trata como null. */
function optDiscountType(v: any): GlobalDiscountType | null {
  const t = s(v).toUpperCase();
  if (t === "PERCENT" || t === "AMOUNT") return t;
  return null;
}

/** Sanitiza el layout config a la forma mínima esperable:
 *    `{ version: number, cards: unknown[] }`.
 *  Si el shape no cumple → devuelve `null` (el frontend cae al default).
 *  No se validan ids/widths individuales — el frontend hace `reconcileLayout`. */
function optLayoutConfig(v: any): InvoiceLayoutConfig | null {
  if (v == null) return null;
  if (typeof v !== "object" || Array.isArray(v)) return null;
  const versionOk = typeof (v as any).version === "number" && Number.isFinite((v as any).version);
  const cardsOk = Array.isArray((v as any).cards);
  if (!versionOk || !cardsOk) return null;
  return v as InvoiceLayoutConfig;
}

/** Sanitiza el objeto opaco `invoiceUiPreferences`. Solo verifica que sea
 *  un objeto plano (no array, no primitive). Las keys/valores específicos
 *  los valida el frontend (`resolveInvoiceUiPreferences`) — el backend
 *  solo persiste el JSON tal cual. */
function optInvoiceUiPreferences(v: any): InvoiceUiPreferences | null {
  if (v == null) return null;
  if (typeof v !== "object" || Array.isArray(v)) return null;
  return v as InvoiceUiPreferences;
}

/** Sanitiza el preset de vista. Solo acepta los 4 valores del enum del
 *  frontend; cualquier otro string (typo, stale, etc.) → null → frontend
 *  cae al default "COMPACT". Mismo patrón defensivo que `optDiscountType`.
 *
 *  COMPAT LEGACY: el enum se renombró en UX.16. Antes incluía "BALANCED"
 *  (= la vista moderna actual que ahora se llama "COMPACT") y "FINANCIAL"
 *  (que se eliminó del enum nuevo). Para no romper a usuarios con valores
 *  persistidos en DB, mapeamos los strings legacy al enum nuevo aquí:
 *    · "BALANCED"  → "COMPACT"
 *    · "FINANCIAL" → null (cae al default "COMPACT" en frontend)
 *  El COMPACT viejo (más angosto) también queda mapeado al COMPACT nuevo;
 *  no hay migración SQL necesaria. */
function optInvoiceViewPreset(v: any): InvoiceViewPreset | null {
  const t = s(v).toUpperCase();
  // Legacy mapping ANTES del check de validez.
  if (t === "BALANCED")     return "COMPACT";
  if (t === "FINANCIAL")    return "COMPACT";
  if (t === "SINGLE_COLUMN") return "COMPACT"; // legacy V1 name
  if (t === "CUSTOM")       return "COMPACT"; // legacy "custom" mode
  return (VALID_INVOICE_VIEW_PRESETS as ReadonlyArray<string>).includes(t)
    ? (t as InvoiceViewPreset)
    : null;
}

function toDTO(row: any): SalesPreferenceDTO {
  const t = row?.defaultGlobalDiscountType;
  const safeType: GlobalDiscountType | null =
    t === "PERCENT" || t === "AMOUNT" ? t : null;
  return {
    scope: SCOPE,
    defaultWarehouseId: row?.defaultWarehouseId ?? null,
    defaultSellerId: row?.defaultSellerId ?? null,
    defaultPriceListId: row?.defaultPriceListId ?? null,
    defaultChannelId: row?.defaultChannelId ?? null,
    defaultCurrencyId: row?.defaultCurrencyId ?? null,
    defaultGlobalDiscountType: safeType,
    invoiceLayoutConfig: optLayoutConfig(row?.invoiceLayoutConfig),
    preferredInvoiceViewPreset: optInvoiceViewPreset(row?.preferredInvoiceViewPreset),
    invoiceUiPreferences: optInvoiceUiPreferences(row?.invoiceUiPreferences),
  };
}

/** Devuelve siempre un DTO (defaults en null si el usuario no tiene fila). */
export async function getMyPreference(jewelryId: string, userId: string): Promise<SalesPreferenceDTO> {
  assert(jewelryId, "Tenant inválido.");
  assert(userId, "Usuario inválido.");

  const row = await prisma.userPreference.findUnique({
    where: { userId_scope: { userId, scope: SCOPE } },
  });

  return toDTO(row);
}

/**
 * Valida que cada id provisto pertenezca al jewelryId del usuario.
 * Si un id es null → se limpia (queda sin preferencia para ese campo).
 */
async function validateOwnership(jewelryId: string, data: {
  defaultWarehouseId: string | null;
  defaultSellerId: string | null;
  defaultPriceListId: string | null;
  defaultChannelId: string | null;
  defaultCurrencyId: string | null;
}) {
  if (data.defaultWarehouseId) {
    const w = await prisma.warehouse.findFirst({
      where: { id: data.defaultWarehouseId, jewelryId },
      select: { id: true },
    });
    assert(w, "El almacén seleccionado no pertenece a la joyería.");
  }
  if (data.defaultSellerId) {
    const x = await prisma.seller.findFirst({
      where: { id: data.defaultSellerId, jewelryId },
      select: { id: true },
    });
    assert(x, "El vendedor seleccionado no pertenece a la joyería.");
  }
  if (data.defaultPriceListId) {
    const x = await prisma.priceList.findFirst({
      where: { id: data.defaultPriceListId, jewelryId },
      select: { id: true },
    });
    assert(x, "La lista de precios seleccionada no pertenece a la joyería.");
  }
  if (data.defaultChannelId) {
    const x = await prisma.salesChannel.findFirst({
      where: { id: data.defaultChannelId, jewelryId },
      select: { id: true },
    });
    assert(x, "El canal de venta seleccionado no pertenece a la joyería.");
  }
  if (data.defaultCurrencyId) {
    const x = await prisma.currency.findFirst({
      where: { id: data.defaultCurrencyId, jewelryId },
      select: { id: true },
    });
    assert(x, "La moneda seleccionada no pertenece a la joyería.");
  }
}

export async function updateMyPreference(
  jewelryId: string,
  userId: string,
  body: any
): Promise<SalesPreferenceDTO> {
  assert(jewelryId, "Tenant inválido.");
  assert(userId, "Usuario inválido.");

  // PATCH parcial: solo tocar los campos cuya KEY esté EXPLÍCITAMENTE en el
  // body. Antes este endpoint funcionaba como "REPLACE completo": un caller
  // que mandaba `{ defaultGlobalDiscountType: "PERCENT" }` borraba en silencio
  // los demás defaults (warehouseId, sellerId, …) porque `optId(undefined)`
  // devuelve `null` y el `update` los pisaba todos. Inversamente, una
  // pantalla que guardaba los 5 ids legacy sin incluir el nuevo campo
  // borraba el favorito del tipo de descuento. Coordinar todos los callers
  // para mandar la "imagen completa" es frágil — el contrato correcto es
  // PATCH: solo se actualiza lo que vino.
  const inBody = (k: string) =>
    body != null && Object.prototype.hasOwnProperty.call(body, k);

  // Sanitización de cada campo desde el body (siempre se calcula; se usa
  // tanto para el `create` —que necesita la imagen completa con nulls— como
  // para `update` —solo los keys presentes).
  const sanitized = {
    defaultWarehouseId:        optId(body?.defaultWarehouseId),
    defaultSellerId:           optId(body?.defaultSellerId),
    defaultPriceListId:        optId(body?.defaultPriceListId),
    defaultChannelId:          optId(body?.defaultChannelId),
    defaultCurrencyId:         optId(body?.defaultCurrencyId),
    defaultGlobalDiscountType: optDiscountType(body?.defaultGlobalDiscountType),
    invoiceLayoutConfig:       optLayoutConfig(body?.invoiceLayoutConfig),
    preferredInvoiceViewPreset: optInvoiceViewPreset(body?.preferredInvoiceViewPreset),
    invoiceUiPreferences:      optInvoiceUiPreferences(body?.invoiceUiPreferences),
  };

  // validateOwnership solo conoce los 5 ids legacy. La pasada se hace ANTES
  // del upsert para fallar temprano si algún id no pertenece al tenant.
  // Cualquier id que NO venga en body queda como `null` aquí (skip-friendly).
  const {
    defaultGlobalDiscountType: _t,
    invoiceLayoutConfig: _l,
    preferredInvoiceViewPreset: _p,
    invoiceUiPreferences: _u,
    ...ownershipPart
  } = sanitized;
  void _t; void _l; void _p; void _u;
  await validateOwnership(jewelryId, ownershipPart);

  // updateData = subconjunto de `sanitized` cuyos keys vinieron en body. Si
  // el caller no mandó la key, no se incluye en el UPDATE de Prisma y el
  // valor existente queda intacto. Para el CREATE inicial usamos `sanitized`
  // completo (las keys ausentes quedan en null, comportamiento de fila nueva).
  const updateData: Record<string, string | null | InvoiceLayoutConfig | InvoiceUiPreferences> = {};
  for (const k of [
    "defaultWarehouseId", "defaultSellerId", "defaultPriceListId",
    "defaultChannelId", "defaultCurrencyId", "defaultGlobalDiscountType",
    "invoiceLayoutConfig", "preferredInvoiceViewPreset", "invoiceUiPreferences",
  ] as const) {
    if (inBody(k)) updateData[k] = (sanitized as Record<string, any>)[k];
  }

  // Prisma 7 — los campos `Json?` requieren `Prisma.JsonNull` cuando se
  // asignan a null (en vez de `null` plano, que tiene otro significado en
  // Json y no es asignable al tipo `NullableJsonNullValueInput`). Mapeamos
  // el `invoiceLayoutConfig` con esta traducción antes del upsert.
  const layoutForPrisma = (v: InvoiceLayoutConfig | null | undefined) =>
    v == null ? Prisma.JsonNull : (v as Prisma.InputJsonValue);
  // Mismo patrón JsonNull para `invoiceUiPreferences` (también Json?).
  const uiPrefsForPrisma = (v: InvoiceUiPreferences | null | undefined) =>
    v == null ? Prisma.JsonNull : (v as Prisma.InputJsonValue);
  const createForPrisma: Prisma.UserPreferenceUncheckedCreateInput = {
    jewelryId, userId, scope: SCOPE,
    defaultWarehouseId:        sanitized.defaultWarehouseId,
    defaultSellerId:           sanitized.defaultSellerId,
    defaultPriceListId:        sanitized.defaultPriceListId,
    defaultChannelId:          sanitized.defaultChannelId,
    defaultCurrencyId:         sanitized.defaultCurrencyId,
    defaultGlobalDiscountType: sanitized.defaultGlobalDiscountType,
    invoiceLayoutConfig:       layoutForPrisma(sanitized.invoiceLayoutConfig),
    preferredInvoiceViewPreset: sanitized.preferredInvoiceViewPreset,
    invoiceUiPreferences:      uiPrefsForPrisma(sanitized.invoiceUiPreferences),
  };
  const updateForPrisma: Prisma.UserPreferenceUncheckedUpdateInput = { jewelryId };
  for (const k of Object.keys(updateData) as Array<keyof typeof updateData>) {
    if (k === "invoiceLayoutConfig") {
      updateForPrisma.invoiceLayoutConfig = layoutForPrisma(
        updateData.invoiceLayoutConfig as InvoiceLayoutConfig | null | undefined,
      );
    } else if (k === "invoiceUiPreferences") {
      updateForPrisma.invoiceUiPreferences = uiPrefsForPrisma(
        updateData.invoiceUiPreferences as InvoiceUiPreferences | null | undefined,
      );
    } else {
      (updateForPrisma as Record<string, unknown>)[k] = updateData[k];
    }
  }

  const row = await prisma.userPreference.upsert({
    where: { userId_scope: { userId, scope: SCOPE } },
    create: createForPrisma,
    update: updateForPrisma,
  });

  return toDTO(row);
}

/* =========================================================================
   HELPERS DE ALMACÉN (consolidación Fase 2)

   UserPreference.defaultWarehouseId es la ÚNICA fuente de verdad del
   "almacén por defecto" del usuario (scope SALES_INVOICE).
   `User.favoriteWarehouseId` queda como fallback LEGACY SOLO LECTURA
   (transitorio): nunca se escribe desde acá.
   Reutilizado por warehouses.service.ts (estrella de Almacenes).
   ========================================================================= */

/**
 * Almacén por defecto efectivo del usuario.
 * 1) UserPreference.defaultWarehouseId (fuente de verdad)
 * 2) fallback LEGACY solo lectura: User.favoriteWarehouseId
 * No valida que el almacén exista/esté activo (eso lo hace el caller).
 */
export async function getSalesDefaultWarehouseId(
  jewelryId: string,
  userId: string
): Promise<string | null> {
  assert(jewelryId, "Tenant inválido.");
  assert(userId, "Usuario inválido.");

  const pref = await prisma.userPreference.findUnique({
    where: { userId_scope: { userId, scope: SCOPE } },
    select: { defaultWarehouseId: true },
  });
  if (pref?.defaultWarehouseId) return pref.defaultWarehouseId;

  // Fallback legacy SOLO LECTURA (no se migra ni se escribe acá).
  const legacy = await prisma.user.findFirst({
    where: { id: userId, jewelryId, deletedAt: null },
    select: { favoriteWarehouseId: true },
  });
  return legacy?.favoriteWarehouseId || null;
}

/**
 * Fija el almacén por defecto del usuario en UserPreference
 * (upsert; preserva los demás defaults). `warehouseId = null` lo limpia.
 * NUNCA toca el legacy User.favoriteWarehouseId.
 */
export async function setSalesDefaultWarehouseId(
  jewelryId: string,
  userId: string,
  warehouseId: string | null
): Promise<void> {
  assert(jewelryId, "Tenant inválido.");
  assert(userId, "Usuario inválido.");
  const wid = warehouseId ? s(warehouseId) : null;

  await prisma.userPreference.upsert({
    where: { userId_scope: { userId, scope: SCOPE } },
    create: { jewelryId, userId, scope: SCOPE, defaultWarehouseId: wid },
    update: { jewelryId, defaultWarehouseId: wid },
  });
}

/**
 * Reasigna el almacén por defecto de TODOS los usuarios del tenant cuyo
 * UserPreference apunta a un almacén que se desactivó/eliminó.
 * Solo opera sobre UserPreference (legacy se autocura lazy en el list).
 */
export async function reassignSalesDefaultWarehouse(
  jewelryId: string,
  removedWarehouseId: string,
  newWarehouseId: string | null
): Promise<void> {
  assert(jewelryId, "Tenant inválido.");
  assert(removedWarehouseId, "Almacén inválido.");

  await prisma.userPreference.updateMany({
    where: {
      jewelryId,
      scope: SCOPE,
      defaultWarehouseId: removedWarehouseId,
    },
    data: { defaultWarehouseId: newWarehouseId },
  });
}
