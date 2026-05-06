// ============================================================================
// combo.utils.ts — Helpers para Combo Comercial
// ----------------------------------------------------------------------------
// Centraliza:
//   · Normalización y validación de campos de combo en Article
//   · Validaciones de componentes (no servicio, no autorreferencia, no ciclos)
//   · Cálculo de disponibilidad del combo según stock de componentes
//
// Convención: las funciones que solo validan datos lanzan Error con .status=400.
// Las funciones que consultan DB son async y reciben Prisma TransactionClient
// opcional para encajar en transacciones del caller.
// ============================================================================
import { Prisma } from "@prisma/client";
import { prisma } from "./prisma.js";

type Db = Prisma.TransactionClient | typeof prisma;

function err(msg: string, status = 400): Error & { status: number } {
  const e: any = new Error(msg);
  e.status = status;
  return e;
}

// ── Fórmula pura del ajuste combo ──────────────────────────────────────────
//
// Recibe el subtotal (suma de componentes) y devuelve el monto final luego del
// ajuste. NO realiza queries; es 100% determinística para tests unitarios.
//
//   NONE              → subtotal sin modificar
//   DISCOUNT_PERCENT  → subtotal − (subtotal × value/100)
//   DISCOUNT_FIXED    → subtotal − value
//   SURCHARGE_PERCENT → subtotal + (subtotal × value/100)
//
// Garantiza que el resultado nunca sea negativo (clamp a 0).
export function applyComboAdjustment(
  subtotal: number,
  kind: ComboAdjustmentKind,
  value: number | null,
): { final: number; adjustmentAmount: number } {
  if (!Number.isFinite(subtotal) || subtotal < 0) {
    return { final: 0, adjustmentAmount: 0 };
  }
  const v = value != null && Number.isFinite(value) ? value : 0;

  let adjustmentAmount = 0;
  let final = subtotal;
  if (kind === "DISCOUNT_PERCENT") {
    adjustmentAmount = (subtotal * v) / 100;
    final = subtotal - adjustmentAmount;
  } else if (kind === "SURCHARGE_PERCENT") {
    adjustmentAmount = (subtotal * v) / 100;
    final = subtotal + adjustmentAmount;
  } else if (kind === "DISCOUNT_FIXED") {
    adjustmentAmount = v;
    final = subtotal - v;
  }
  if (final < 0) final = 0;
  return { final, adjustmentAmount };
}

// ── Constantes ─────────────────────────────────────────────────────────────
export const COMMERCIAL_MODES = new Set(["NORMAL", "COMBO_COMMERCIAL"] as const);
export const COMBO_ADJUSTMENT_KINDS = new Set(
  ["NONE", "DISCOUNT_PERCENT", "DISCOUNT_FIXED", "SURCHARGE_PERCENT"] as const,
);

export type CommercialMode = "NORMAL" | "COMBO_COMMERCIAL";
export type ComboAdjustmentKind =
  | "NONE"
  | "DISCOUNT_PERCENT"
  | "DISCOUNT_FIXED"
  | "SURCHARGE_PERCENT";

// ── Línea mínima requerida por las validaciones (subset de ArticleCostLine) ─
export type ComboCostLineInput = {
  type?: string;
  catalogItemId?: string | null;
  quantity?: number | string | null;
  affectsStock?: boolean;
};

// ── Normalización de campos combo ───────────────────────────────────────────
//
// Cuando commercialMode === "COMBO_COMMERCIAL", un combo NO maneja stock propio
// y su precio es derivado. Forzamos:
//   · stockMode             → "NO_STOCK"
//   · sellWithoutVariants   → true (etapa actual; mañana puede relajarse)
//   · useManualSalePrice    → false
//
// También valida obligatoriedad / formato de comboAdjustmentValue según kind.
export function normalizeComboFields(input: {
  articleType?: string;
  commercialMode?: string;
  comboAdjustmentKind?: string;
  comboAdjustmentValue?: number | string | null;
  stockMode?: string;
  sellWithoutVariants?: boolean;
  useManualSalePrice?: boolean;
}): {
  commercialMode: CommercialMode;
  comboAdjustmentKind: ComboAdjustmentKind;
  comboAdjustmentValue: number | null;
  stockMode?: string;
  sellWithoutVariants?: boolean;
} {
  const commercialMode = COMMERCIAL_MODES.has(input.commercialMode as any)
    ? (input.commercialMode as CommercialMode)
    : "NORMAL";

  const comboAdjustmentKind = COMBO_ADJUSTMENT_KINDS.has(input.comboAdjustmentKind as any)
    ? (input.comboAdjustmentKind as ComboAdjustmentKind)
    : "NONE";

  let comboAdjustmentValue: number | null = null;

  if (commercialMode === "COMBO_COMMERCIAL") {
    if (input.articleType && input.articleType !== "PRODUCT") {
      throw err("Un combo comercial solo puede aplicarse a artículos de tipo PRODUCT.");
    }

    // Validación del valor según kind
    if (comboAdjustmentKind === "NONE") {
      // En NONE el valor debe ser null (suma directa, sin ajuste)
      comboAdjustmentValue = null;
    } else {
      const raw = input.comboAdjustmentValue;
      if (raw == null || raw === "") {
        throw err("El valor del ajuste del combo es obligatorio cuando el ajuste no es 'Suma directa'.");
      }
      const n = typeof raw === "number" ? raw : parseFloat(String(raw));
      if (!Number.isFinite(n)) {
        throw err("El valor del ajuste del combo debe ser un número válido.");
      }
      if (comboAdjustmentKind === "DISCOUNT_PERCENT" || comboAdjustmentKind === "SURCHARGE_PERCENT") {
        if (n < 0 || n > 100) {
          throw err("El porcentaje de ajuste del combo debe estar entre 0 y 100.");
        }
      } else if (comboAdjustmentKind === "DISCOUNT_FIXED") {
        if (n < 0) {
          throw err("El descuento fijo del combo no puede ser negativo.");
        }
      }
      comboAdjustmentValue = n;
    }

    return {
      commercialMode,
      comboAdjustmentKind,
      comboAdjustmentValue,
      // Flags forzados (siguen aplicando):
      //  · stockMode = NO_STOCK: el combo no maneja stock propio (se descuenta de componentes)
      //  · sellWithoutVariants = true: en esta etapa los combos no tienen variantes
      // Lo que NO se fuerza: useManualSalePrice y salePrice quedan editables.
      // El combo se comporta como cualquier producto a nivel pricing comercial:
      // puede tener lista de precios, salePrice manual con override, o quedar sin precio.
      stockMode: "NO_STOCK",
      sellWithoutVariants: true,
    };
  }

  // commercialMode === "NORMAL" → valores combo se descartan (default seguro)
  return {
    commercialMode: "NORMAL",
    comboAdjustmentKind: "NONE",
    comboAdjustmentValue: null,
    // No forzar stockMode/variants/manualPrice cuando NORMAL → lo decide el caller
  };
}

// ── Validación de componentes (sin acceso a DB) ─────────────────────────────
//
// Se invoca para combos comerciales. Recibe las líneas que el usuario quiere
// guardar en costComposition. Solo valida estructura; las consultas a otros
// artículos (servicio? eliminado?) las hace `validateComboComponentsAgainstDb`.
export function validateComboComponentsShape(opts: {
  ownArticleId?: string | null;       // null en createArticle (todavía no existe)
  componentLines: ComboCostLineInput[];
}): void {
  const { ownArticleId, componentLines } = opts;

  const componentRefs = componentLines.filter(
    (l) => (l.type === "PRODUCT" || l.type === "SERVICE") && l.catalogItemId,
  );

  if (componentRefs.length === 0) {
    throw err("El combo comercial debe tener al menos un componente.");
  }

  const seen = new Set<string>();
  for (const l of componentRefs) {
    const id = l.catalogItemId!;
    if (ownArticleId && id === ownArticleId) {
      throw err("Un combo no puede contenerse a sí mismo como componente.");
    }
    if (seen.has(id)) {
      throw err("Hay componentes duplicados en el combo. Sumá la cantidad en una sola línea.");
    }
    seen.add(id);

    const qty = typeof l.quantity === "number" ? l.quantity : parseFloat(String(l.quantity ?? 0));
    if (!Number.isFinite(qty) || qty <= 0) {
      throw err("La cantidad de cada componente del combo debe ser mayor a 0.");
    }

    // Por consistencia visual: en combos las líneas de componente deben afectar stock.
    // El service del artículo lo fuerza a true al guardar; esta validación es defensiva.
    // (No bloqueamos si viene false: el service lo normaliza.)
  }
}

// ── Validación contra DB: tipo, estado, ciclos ──────────────────────────────
//
// Verifica que cada componente:
//   · Exista, pertenezca al tenant, no esté soft-deleted
//   · Sea articleType=PRODUCT (no servicios ni materiales — los servicios se
//     manejan como ArticleCostLine.type=SERVICE separado, no como componente
//     vendible de stock)
//   · Si el componente es a su vez COMBO_COMMERCIAL, no genere ciclo con el
//     artículo padre (ownArticleId)
export async function validateComboComponentsAgainstDb(
  db: Db,
  opts: {
    jewelryId: string;
    ownArticleId?: string | null;
    componentArticleIds: string[];
  },
): Promise<void> {
  const { jewelryId, ownArticleId, componentArticleIds } = opts;
  if (componentArticleIds.length === 0) return;

  const components = await db.article.findMany({
    where: { id: { in: componentArticleIds }, jewelryId, deletedAt: null },
    select: { id: true, name: true, code: true, articleType: true, commercialMode: true, isActive: true },
  });
  const byId = new Map(components.map((c) => [c.id, c]));

  for (const cid of componentArticleIds) {
    const c = byId.get(cid);
    if (!c) {
      throw err(`Un componente del combo no existe o fue eliminado (${cid.slice(0, 8)}…).`);
    }
    if (c.articleType === "SERVICE") {
      throw err(
        `El componente "${c.name}" (${c.code}) es un Servicio y no puede formar parte de un combo comercial.`,
      );
    }
    if (!c.isActive) {
      throw err(`El componente "${c.name}" (${c.code}) está inactivo.`);
    }
  }

  // Ciclos: si algún componente es a su vez combo, hacer DFS en DB.
  if (ownArticleId) {
    for (const cid of componentArticleIds) {
      const reachesOwn = await comboReachesTarget(db, {
        jewelryId,
        startId: cid,
        targetId: ownArticleId,
        visited: new Set<string>(),
      });
      if (reachesOwn) {
        const c = byId.get(cid)!;
        throw err(
          `Ciclo detectado: el componente "${c.name}" (${c.code}) ya contiene este combo en su composición.`,
        );
      }
    }
  }
}

// ── DFS recursivo: ¿`startId` (siguiendo componentes combo) llega a `targetId`?
async function comboReachesTarget(
  db: Db,
  opts: { jewelryId: string; startId: string; targetId: string; visited: Set<string> },
): Promise<boolean> {
  const { jewelryId, startId, targetId, visited } = opts;
  if (startId === targetId) return true;
  if (visited.has(startId)) return false;
  visited.add(startId);

  const node = await db.article.findFirst({
    where: { id: startId, jewelryId, deletedAt: null },
    select: {
      commercialMode: true,
      costComposition: {
        where: { type: { in: ["PRODUCT", "SERVICE"] }, catalogItemId: { not: null } },
        select: { catalogItemId: true },
      },
    },
  });
  if (!node) return false;
  // Si no es combo, dejamos de bajar (sus líneas PRODUCT no son componentes de combo
  // sino componentes de costo; no propagan al combo padre).
  if (node.commercialMode !== "COMBO_COMMERCIAL") return false;

  for (const l of node.costComposition) {
    const childId = l.catalogItemId!;
    if (await comboReachesTarget(db, { jewelryId, startId: childId, targetId, visited })) {
      return true;
    }
  }
  return false;
}

// ── Disponibilidad del combo ────────────────────────────────────────────────
//
// Calcula cuántos combos pueden venderse según el stock actual de los componentes.
// Fórmula: floor( min(stock_componente_i / qty_componente_i) ) para cada componente
// con affectsStock=true. Si no hay almacén indicado, suma stocks de todos los almacenes.
//
// Devuelve además un detalle por componente para que el frontend muestre
// el cuello de botella ("máximo X según stock de Y").
export async function computeComboAvailability(
  db: Db,
  opts: { jewelryId: string; articleId: string; warehouseId?: string | null },
): Promise<{
  available: number;
  isCombo: boolean;
  components: Array<{
    articleId: string;
    code: string;
    name: string;
    qtyPerCombo: number;
    stock: number;
    canMake: number;
  }>;
  bottleneckArticleId: string | null;
}> {
  const { jewelryId, articleId, warehouseId } = opts;

  const article = await db.article.findFirst({
    where: { id: articleId, jewelryId, deletedAt: null },
    select: {
      commercialMode: true,
      costComposition: {
        where: {
          type: { in: ["PRODUCT", "SERVICE"] },
          affectsStock: true,
          catalogItemId: { not: null },
        },
        select: {
          catalogItemId: true,
          quantity: true,
          catalogItem: { select: { id: true, code: true, name: true } },
        },
      },
    },
  });

  if (!article) {
    throw err("Artículo no encontrado.", 404);
  }
  if (article.commercialMode !== "COMBO_COMMERCIAL") {
    return { available: 0, isCombo: false, components: [], bottleneckArticleId: null };
  }
  if (article.costComposition.length === 0) {
    return { available: 0, isCombo: true, components: [], bottleneckArticleId: null };
  }

  const componentIds = article.costComposition
    .map((l) => l.catalogItemId)
    .filter((x): x is string => !!x);

  // Stock por componente (suma de variantes y opcionalmente de un almacén específico).
  // ArticleStock keyado por (article, variant?, warehouse). Si el componente no maneja
  // variantes, hay un único registro con variantId=null. Sumamos todos los matches.
  const stockRows = await db.articleStock.findMany({
    where: {
      jewelryId,
      articleId: { in: componentIds },
      ...(warehouseId ? { warehouseId } : {}),
    },
    select: { articleId: true, quantity: true },
  });
  const stockByArticle = new Map<string, number>();
  for (const r of stockRows) {
    const cur = stockByArticle.get(r.articleId) ?? 0;
    stockByArticle.set(r.articleId, cur + Number(r.quantity));
  }

  let minCanMake = Infinity;
  let bottleneckArticleId: string | null = null;
  const components = article.costComposition.map((l) => {
    const qtyPerCombo = Number(l.quantity);
    const stock = stockByArticle.get(l.catalogItemId!) ?? 0;
    const canMake = qtyPerCombo > 0 ? Math.floor(stock / qtyPerCombo) : 0;
    if (canMake < minCanMake) {
      minCanMake = canMake;
      bottleneckArticleId = l.catalogItemId!;
    }
    return {
      articleId: l.catalogItemId!,
      code: l.catalogItem?.code ?? "",
      name: l.catalogItem?.name ?? "",
      qtyPerCombo,
      stock,
      canMake,
    };
  });

  return {
    available: minCanMake === Infinity ? 0 : Math.max(0, minCanMake),
    isCombo: true,
    components,
    bottleneckArticleId,
  };
}
