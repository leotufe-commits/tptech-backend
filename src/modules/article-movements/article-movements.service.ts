import { Prisma } from "@prisma/client";
import { prisma } from "../../lib/prisma.js";
import {
  validateStockLineIntegrity,
  applyMovementImpact,
  reverseMovementImpact,
} from "../../lib/stock-engine.js";

type Kind = "IN" | "OUT" | "TRANSFER" | "ADJUST" | "OPENING";

function s(v: any): string { return String(v ?? "").trim(); }
function toDec(v: any): Prisma.Decimal | null {
  const raw = String(v ?? "").trim().replace(/\s/g, "").replace(",", ".");
  if (!raw) return null;
  const n = Number(raw);
  if (!Number.isFinite(n)) return null;
  return new Prisma.Decimal(raw);
}
function assert(cond: any, msg: string, status = 400): void {
  if (!cond) { const e: any = new Error(msg); e.status = status; throw e; }
}
function clampTake(v: any, fallback = 50): number {
  const n = Number(v);
  return Number.isFinite(n) ? Math.max(1, Math.min(200, Math.floor(n))) : fallback;
}

// ===========================================================================
// Código correlativo por tenant + kind
// Formato: AE-NNNN (IN), AS-NNNN (OUT), AT-NNNN (TRANSFER),
//          AA-NNNN (ADJUST), AO-NNNN (OPENING)
// Se cuentan TODOS los movimientos incluyendo anulados para no reutilizar números.
// ===========================================================================
const KIND_PREFIX: Record<Kind, string> = {
  IN:       "AE",
  OUT:      "AS",
  TRANSFER: "AT",
  ADJUST:   "AA",
  OPENING:  "AO",
};

async function generateCode(tx: Prisma.TransactionClient, jewelryId: string, kind: Kind): Promise<string> {
  const prefix = KIND_PREFIX[kind];
  // Contar incluyendo anulados para que el código nunca se reutilice
  const count = await tx.articleMovement.count({ where: { jewelryId, kind } });
  return `${prefix}-${String(count + 1).padStart(4, "0")}`;
}

// ===========================================================================
// Validaciones comunes de líneas
// ===========================================================================
type RawLine = { articleId: string; variantId?: string | null; quantity: any; weightPerUnit?: any };

function parseLines(raw: any[]): Array<{
  articleId: string;
  variantId: string | null;
  quantity: Prisma.Decimal;
  weightPerUnit: Prisma.Decimal | null;
}> {
  return (raw ?? [])
    .map((l) => ({
      articleId:    s(l?.articleId),
      variantId:    s(l?.variantId) || null,
      quantity:     toDec(l?.quantity),
      weightPerUnit: toDec(l?.weightPerUnit) ?? null,
    }))
    .filter((l) => l.articleId && l.quantity !== null) as any;
}

async function validateLinesForStock(
  tx: Prisma.TransactionClient,
  jewelryId: string,
  lines: Array<{ articleId: string; variantId: string | null; quantity: Prisma.Decimal }>
) {
  // Delegar al motor central: garantiza variant vs parent, BY_ARTICLE, tenant isolation
  for (const line of lines) {
    await validateStockLineIntegrity(tx, jewelryId, line);
  }
}

// ===========================================================================
// Resolución de peso por línea
// Regla: solo se resuelve peso si el artículo tiene composiciones de metal reales.
// Prioridad: weightPerUnit del usuario → weightOverride de la variante →
//            suma de líneas METAL en costComposition → weight del artículo (legacy).
// El valor resuelto se guarda como snapshot; nunca se recalcula después.
// ===========================================================================
type ParsedLine = {
  articleId: string;
  variantId: string | null;
  quantity: Prisma.Decimal;
  weightPerUnit: Prisma.Decimal | null;
};

async function resolveLineWeights(
  tx: Prisma.TransactionClient,
  jewelryId: string,
  lines: ParsedLine[]
): Promise<Array<ParsedLine & { resolvedWeightPerUnit: Prisma.Decimal | null }>> {
  return Promise.all(
    lines.map(async (l) => {
      // Verificar si el artículo realmente tiene composiciones de metal.
      // Sin metales → peso siempre null, independientemente de lo que envíe el cliente.
      const metalLines = await tx.articleCostLine.findMany({
        where: {
          articleId: l.articleId,
          jewelryId,
          type: "METAL" as any,
          quantity: { gt: 0 },
        },
        select: { quantity: true },
      });
      if (metalLines.length === 0) {
        return { ...l, resolvedWeightPerUnit: null };
      }

      // Si el usuario ya proporcionó un peso, usarlo directamente
      if (l.weightPerUnit != null && l.weightPerUnit.gt(0)) {
        return { ...l, resolvedWeightPerUnit: l.weightPerUnit };
      }

      // Fallback 1: weightOverride de la variante
      if (l.variantId) {
        const variant = await tx.articleVariant.findFirst({
          where: { id: l.variantId, jewelryId, deletedAt: null },
          select: { weightOverride: true },
        });
        if (variant?.weightOverride != null && new Prisma.Decimal(variant.weightOverride).gt(0)) {
          return { ...l, resolvedWeightPerUnit: new Prisma.Decimal(variant.weightOverride) };
        }
      }

      // Fallback 2: suma de gramos de las líneas METAL (fuente de verdad principal)
      const sumGrams = metalLines.reduce(
        (acc, ml) => acc.add(new Prisma.Decimal(ml.quantity.toString())),
        new Prisma.Decimal(0)
      );
      if (sumGrams.gt(0)) return { ...l, resolvedWeightPerUnit: sumGrams };

      // Fallback 3: weight del artículo (campo legacy)
      const article = await tx.article.findFirst({
        where: { id: l.articleId, jewelryId, deletedAt: null },
        select: { weight: true },
      });
      if (article?.weight != null && new Prisma.Decimal(article.weight).gt(0)) {
        return { ...l, resolvedWeightPerUnit: new Prisma.Decimal(article.weight) };
      }

      return { ...l, resolvedWeightPerUnit: null };
    })
  );
}

// ===========================================================================
// Select compartido para líneas de movimiento
// Incluye costComposition del artículo para discriminar gramos por variante de metal
// en la vista de detalle.
// ===========================================================================
const LINE_SELECT = {
  id: true,
  articleId: true,
  variantId: true,
  quantity: true,
  weightPerUnit: true,
  totalWeight: true,
  snapshot: true,
  article: {
    select: {
      id: true,
      code: true,
      name: true,
      sku: true,
      mainImageUrl: true,
      costComposition: {
        where: { type: "METAL" as any, quantity: { gt: 0 } },
        select: {
          quantity: true,
          metalVariantId: true,
          metalVariant: {
            select: {
              id: true,
              name: true,
              metal: { select: { name: true } },
            },
          },
        },
        orderBy: { sortOrder: "asc" as const },
      },
    },
  },
  variant: { select: { id: true, code: true, name: true, sku: true, imageUrl: true } },
} as const;

// ===========================================================================
// Enriquecimiento de líneas: agrega metals[] y elimina costComposition del response.
// metals[i].gramsUnit = costComposition[i].quantity (gramos por unidad para ese metal)
// metals[i].gramsTotal = gramsUnit × abs(lineQuantity)
// El frontend NO recalcula — solo muestra los valores devueltos aquí.
// ===========================================================================
// snapshotWeightPerUnit = weightPerUnit guardado en el movimiento (puede venir de override o suma).
// Si difiere de sum(composition), los gramos por metal se distribuyen proporcionalmente
// para garantizar: sum(metals[i].gramsUnit) === snapshotWeightPerUnit siempre.
function computeLineMetals(
  costComposition: Array<{
    quantity: any;
    metalVariantId: string | null;
    metalVariant: { id: string; name: string; metal: { name: string } } | null;
  }>,
  lineQuantity: any,
  snapshotWeightPerUnit: any
): Array<{ metalVariantId: string | null; name: string; gramsUnit: number; gramsTotal: number }> {
  const qty      = Math.abs(Number(lineQuantity));
  const validMetals = costComposition.filter(c => Number(c.quantity) > 0);
  if (validMetals.length === 0) return [];

  const compSum = validMetals.reduce((sum, c) => sum + Number(c.quantity), 0);
  const wpu     = Number(snapshotWeightPerUnit);

  // Distribución proporcional si el snapshot difiere de la composición (weightOverride o
  // peso ingresado manualmente por el usuario). Garantiza sum(gramsUnit) === weightPerUnit.
  const useProportional = wpu > 0 && compSum > 0 && Math.abs(wpu - compSum) > 0.0001;

  return validMetals.map(c => {
    const gramsUnit = useProportional
      ? wpu * (Number(c.quantity) / compSum)
      : Number(c.quantity);
    return {
      metalVariantId: c.metalVariantId,
      name:           c.metalVariant?.name ?? c.metalVariant?.metal?.name ?? "Metal",
      gramsUnit,
      gramsTotal:     gramsUnit * qty,
    };
  });
}

// ===========================================================================
// Construye snapshots para cada línea en el momento de creación.
// Usa los datos actuales de artículo/variante/composición metálica para
// preservar nombres, imágenes y gramos aunque el artículo sea renombrado después.
// Se llama en una transacción activa (dentro de createArticleMovement / transferArticleMovement).
// ===========================================================================
async function buildLineSnapshots(
  tx: Prisma.TransactionClient,
  jewelryId: string,
  resolvedLines: Array<ParsedLine & { resolvedWeightPerUnit: Prisma.Decimal | null }>
): Promise<Map<number, any>> {
  const articleIds = [...new Set(resolvedLines.map((l) => l.articleId))];
  const variantIds = [...new Set(resolvedLines.map((l) => l.variantId).filter((v): v is string => v != null))];

  const [articles, variants] = await Promise.all([
    tx.article.findMany({
      where: { id: { in: articleIds }, jewelryId },
      select: {
        id: true,
        code: true,
        name: true,
        sku: true,
        mainImageUrl: true,
        costComposition: {
          where: { type: "METAL" as any, quantity: { gt: 0 } },
          select: {
            quantity: true,
            metalVariantId: true,
            metalVariant: {
              select: {
                id: true,
                name: true,
                metal: { select: { name: true } },
              },
            },
          },
          orderBy: { sortOrder: "asc" as const },
        },
      },
    }),
    variantIds.length > 0
      ? tx.articleVariant.findMany({
          where: { id: { in: variantIds }, jewelryId },
          select: { id: true, code: true, name: true, sku: true, imageUrl: true },
        })
      : Promise.resolve([]),
  ]);

  const articleMap = new Map(articles.map((a) => [a.id, a]));
  const variantMap = new Map(variants.map((v) => [v.id, v]));

  const snapshots = new Map<number, any>();
  resolvedLines.forEach((l, i) => {
    const article = articleMap.get(l.articleId);
    if (!article) return;
    const variant = l.variantId ? (variantMap.get(l.variantId) ?? null) : null;

    const qty    = Math.abs(Number(l.quantity));
    const wpu    = l.resolvedWeightPerUnit ? Number(l.resolvedWeightPerUnit) : 0;
    const validComp = article.costComposition.filter((c) => Number(c.quantity) > 0);
    const compSum   = validComp.reduce((s, c) => s + Number(c.quantity), 0);
    const useProportional = wpu > 0 && compSum > 0 && Math.abs(wpu - compSum) > 0.0001;

    const metals = validComp.map((c) => {
      const gramsUnit = useProportional
        ? wpu * (Number(c.quantity) / compSum)
        : Number(c.quantity);
      return {
        metalVariantId:   c.metalVariantId,
        metalVariantName: c.metalVariant?.name ?? c.metalVariant?.metal?.name ?? "Metal",
        metalName:        c.metalVariant?.metal?.name ?? c.metalVariant?.name ?? "Metal",
        gramsUnit,
        gramsTotal: gramsUnit * qty,
      };
    });

    snapshots.set(i, {
      articleName:  article.name,
      articleCode:  article.code,
      articleSku:   article.sku,
      articleImage: article.mainImageUrl || null,
      variantName:  variant?.name  ?? null,
      variantCode:  variant?.code  ?? null,
      variantSku:   variant?.sku   ?? null,
      variantImage: variant?.imageUrl ?? null,
      metals,
    });
  });

  return snapshots;
}

function enrichMovement(movement: any): any {
  return {
    ...movement,
    lines: (movement.lines ?? []).map((line: any) => {
      const snap = (line.snapshot as any) ?? null;

      if (snap) {
        // Usar snapshot — protege contra renombres y cambios de composición posteriores
        const liveArticle: any = line.article ?? {};
        const article = {
          id:           liveArticle.id   ?? line.articleId,
          code:         snap.articleCode,
          name:         snap.articleName,
          sku:          snap.articleSku,
          mainImageUrl: snap.articleImage ?? liveArticle.mainImageUrl ?? null,
        };
        const variant = line.variantId
          ? {
              id:       (line.variant as any)?.id       ?? line.variantId,
              code:     snap.variantCode  ?? (line.variant as any)?.code  ?? "",
              name:     snap.variantName  ?? (line.variant as any)?.name  ?? "",
              sku:      snap.variantSku   ?? (line.variant as any)?.sku   ?? "",
              imageUrl: snap.variantImage ?? (line.variant as any)?.imageUrl ?? null,
            }
          : null;
        const metals: Array<{ metalVariantId: string | null; name: string; gramsUnit: number; gramsTotal: number }> =
          (snap.metals ?? []).map((m: any) => ({
            metalVariantId: m.metalVariantId,
            name:           m.metalVariantName,
            gramsUnit:      m.gramsUnit,
            gramsTotal:     m.gramsTotal,
          }));
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        const { snapshot: _snap, ...lineWithoutSnap } = line;
        return { ...lineWithoutSnap, article, variant, metals };
      }

      // Fallback legacy: computar desde costComposition en vivo
      const costComposition = line.article?.costComposition ?? [];
      const metals = computeLineMetals(costComposition, line.quantity, line.weightPerUnit);
      const { costComposition: _cc, ...articleWithoutComp } = line.article ?? {};
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { snapshot: _snap2, ...lineWithoutSnap2 } = line;
      return {
        ...lineWithoutSnap2,
        article: line.article ? articleWithoutComp : null,
        metals,
      };
    }),
  };
}

// ===========================================================================
// List movements
// ===========================================================================
export async function listArticleMovements(opts: {
  jewelryId: string;
  page?: number;
  pageSize?: number;
  q?: string;
  warehouseId?: string | null;
  kind?: string | null;
  from?: Date | null;
  to?: Date | null;
  articleId?: string | null;
  variantId?: string | null;
}) {
  const { jewelryId } = opts;
  const take = clampTake(opts.pageSize ?? 50);
  const skip = (Math.max(1, opts.page ?? 1) - 1) * take;

  const q = s(opts.q || "");
  const where: any = { jewelryId, status: { not: "VOIDED" } };

  if (opts.kind) where.kind = opts.kind;
  if (opts.warehouseId) {
    where.OR = [
      { warehouseId: opts.warehouseId },
      { fromWarehouseId: opts.warehouseId },
      { toWarehouseId: opts.warehouseId },
    ];
  }
  if (opts.from || opts.to) {
    where.effectiveAt = {};
    if (opts.from) where.effectiveAt.gte = opts.from;
    if (opts.to) where.effectiveAt.lte = opts.to;
  }
  if (opts.articleId || opts.variantId) {
    const lineFilter: Record<string, string> = {};
    if (opts.articleId) lineFilter.articleId = opts.articleId;
    if (opts.variantId) lineFilter.variantId = opts.variantId;
    where.lines = { some: lineFilter };
  }
  if (q) {
    where.OR = [
      ...(where.OR ?? []),
      { note: { contains: q, mode: "insensitive" } },
      { code: { contains: q, mode: "insensitive" } },
    ];
  }

  const [total, rows] = await prisma.$transaction([
    prisma.articleMovement.count({ where }),
    prisma.articleMovement.findMany({
      where,
      orderBy: [{ effectiveAt: "desc" }, { createdAt: "desc" }],
      skip,
      take,
      select: {
        id: true,
        kind: true,
        status: true,
        sourceType: true,
        code: true,
        note: true,
        effectiveAt: true,
        voidedAt: true,
        voidedNote: true,
        createdAt: true,
        warehouse:     { select: { id: true, name: true, code: true } },
        fromWarehouse: { select: { id: true, name: true, code: true } },
        toWarehouse:   { select: { id: true, name: true, code: true } },
        createdBy:     { select: { id: true, name: true, email: true } },
        voidedBy:      { select: { id: true, name: true, email: true } },
        lines: { select: LINE_SELECT },
      },
    }),
  ]);

  return { rows: rows.map(enrichMovement), total, page: opts.page ?? 1, pageSize: take };
}

// ===========================================================================
// Create — IN / OUT / ADJUST / OPENING
// ===========================================================================
export async function createArticleMovement(opts: {
  jewelryId: string;
  userId: string;
  kind: Exclude<Kind, "TRANSFER">;
  warehouseId: string;
  effectiveAt: Date;
  note?: string;
  lines: RawLine[];
}) {
  const { jewelryId, userId } = opts;
  assert(jewelryId, "Tenant inválido.");
  assert(userId, "Usuario inválido.");
  assert(opts.warehouseId, "Almacén requerido.");
  assert(["IN", "OUT", "ADJUST", "OPENING"].includes(opts.kind), "Tipo de movimiento inválido.");

  const lines = parseLines(opts.lines);
  assert(lines.length > 0, "Agregá al menos una línea.");

  // Validación de cantidades por tipo de movimiento
  for (const l of lines) {
    if (opts.kind === "ADJUST") {
      // ADJUST: delta firmado — positivo o negativo, nunca cero
      assert(!l.quantity.eq(0), `El delta de ajuste no puede ser 0. (artículo: ${l.articleId})`);
    } else {
      // IN / OUT / OPENING: magnitud positiva
      assert(l.quantity.gt(0), `La cantidad debe ser mayor a 0. (artículo: ${l.articleId})`);
    }
  }

  return prisma.$transaction(async (tx) => {
    const wh = await tx.warehouse.findFirst({
      where: { id: opts.warehouseId, jewelryId, deletedAt: null },
      select: { id: true, isActive: true },
    });
    assert(wh, "Almacén no encontrado.");
    assert(wh!.isActive, "El almacén está inactivo.");

    await validateLinesForStock(tx, jewelryId, lines);

    // OPENING: no se permite si el artículo ya tiene stock en este almacén
    if (opts.kind === "OPENING") {
      for (const line of lines) {
        const existing = await tx.articleStock.findFirst({
          where: {
            jewelryId,
            warehouseId: opts.warehouseId,
            articleId:   line.articleId,
            variantId:   line.variantId ?? null,
          },
          select: { id: true },
        });
        assert(
          !existing,
          "No se puede registrar Apertura: el artículo ya tiene stock en este almacén. Usá Ajuste para modificar el stock existente."
        );
      }
    }

    // Aplicar impacto al stock vía motor central
    const { hasNegativeStock } = await applyMovementImpact(tx, {
      kind:        opts.kind,
      jewelryId,
      warehouseId: opts.warehouseId,
      lines,
    });

    const code = await generateCode(tx, jewelryId, opts.kind);

    // Resolver peso efectivo por línea (fallback a variante/artículo si el usuario no lo ingresó)
    const resolvedLines = await resolveLineWeights(tx, jewelryId, lines);

    // Construir snapshots históricos (write-once: nombre, imagen, gramos por metal al momento de crear)
    const lineSnapshots = await buildLineSnapshots(tx, jewelryId, resolvedLines);

    const movement = await tx.articleMovement.create({
      data: {
        jewelryId,
        kind:   opts.kind,
        status: "CONFIRMED",
        sourceType: "MANUAL",
        code,
        note: s(opts.note || ""),
        effectiveAt: opts.effectiveAt ?? new Date(),
        warehouseId: opts.warehouseId,
        createdById: userId || null,
        lines: {
          create: resolvedLines.map((l, i) => {
            const wpu = l.resolvedWeightPerUnit;
            const tw  = wpu != null ? l.quantity.abs().mul(wpu) : null;
            return {
              jewelryId,
              articleId:     l.articleId,
              variantId:     l.variantId ?? null,
              quantity:      l.quantity,
              weightPerUnit: wpu,
              totalWeight:   tw,
              snapshot:      lineSnapshots.get(i) ?? null,
            };
          }),
        },
      },
      select: {
        id: true,
        kind: true,
        status: true,
        sourceType: true,
        code: true,
        note: true,
        effectiveAt: true,
        createdAt: true,
        warehouse:  { select: { id: true, name: true, code: true } },
        createdBy:  { select: { id: true, name: true, email: true } },
        lines: { select: LINE_SELECT },
      },
    });

    return enrichMovement({ ...movement, hasNegativeStock });
  });
}

// ===========================================================================
// Transfer
// ===========================================================================
export async function transferArticleMovement(opts: {
  jewelryId: string;
  userId: string;
  fromWarehouseId: string;
  toWarehouseId: string;
  effectiveAt: Date;
  note?: string;
  lines: RawLine[];
}) {
  const { jewelryId, userId } = opts;
  assert(jewelryId, "Tenant inválido.");
  assert(userId, "Usuario inválido.");
  assert(opts.fromWarehouseId, "Almacén origen requerido.");
  assert(opts.toWarehouseId, "Almacén destino requerido.");
  assert(opts.fromWarehouseId !== opts.toWarehouseId, "Origen y destino no pueden ser el mismo.");

  const lines = parseLines(opts.lines);
  assert(lines.length > 0, "Agregá al menos una línea.");
  for (const l of lines) {
    assert(l.quantity.gt(0), `La cantidad debe ser mayor a 0. (artículo: ${l.articleId})`);
  }

  return prisma.$transaction(async (tx) => {
    const [fromWh, toWh] = await Promise.all([
      tx.warehouse.findFirst({ where: { id: opts.fromWarehouseId, jewelryId, deletedAt: null }, select: { id: true, isActive: true } }),
      tx.warehouse.findFirst({ where: { id: opts.toWarehouseId, jewelryId, deletedAt: null }, select: { id: true, isActive: true } }),
    ]);
    assert(fromWh, "Almacén origen no encontrado.");
    assert(toWh, "Almacén destino no encontrado.");
    assert(fromWh!.isActive, "El almacén origen está inactivo.");
    assert(toWh!.isActive, "El almacén destino está inactivo.");

    await validateLinesForStock(tx, jewelryId, lines);

    // Aplicar impacto al stock vía motor central
    const { hasNegativeStock } = await applyMovementImpact(tx, {
      kind:            "TRANSFER",
      jewelryId,
      fromWarehouseId: opts.fromWarehouseId,
      toWarehouseId:   opts.toWarehouseId,
      lines,
    });

    const code = await generateCode(tx, jewelryId, "TRANSFER");

    // Resolver peso efectivo por línea (fallback a variante/artículo si el usuario no lo ingresó)
    const resolvedLines = await resolveLineWeights(tx, jewelryId, lines);

    // Construir snapshots históricos (write-once)
    const lineSnapshots = await buildLineSnapshots(tx, jewelryId, resolvedLines);

    const movement = await tx.articleMovement.create({
      data: {
        jewelryId,
        kind:   "TRANSFER",
        status: "CONFIRMED",
        sourceType: "MANUAL",
        code,
        note: s(opts.note || ""),
        effectiveAt: opts.effectiveAt ?? new Date(),
        fromWarehouseId: opts.fromWarehouseId,
        toWarehouseId:   opts.toWarehouseId,
        createdById: userId || null,
        lines: {
          create: resolvedLines.map((l, i) => {
            const wpu = l.resolvedWeightPerUnit;
            const tw  = wpu != null ? l.quantity.abs().mul(wpu) : null;
            return {
              jewelryId,
              articleId:     l.articleId,
              variantId:     l.variantId ?? null,
              quantity:      l.quantity,
              weightPerUnit: wpu,
              totalWeight:   tw,
              snapshot:      lineSnapshots.get(i) ?? null,
            };
          }),
        },
      },
      select: {
        id: true,
        kind: true,
        status: true,
        sourceType: true,
        code: true,
        note: true,
        effectiveAt: true,
        createdAt: true,
        fromWarehouse: { select: { id: true, name: true, code: true } },
        toWarehouse:   { select: { id: true, name: true, code: true } },
        createdBy:     { select: { id: true, name: true, email: true } },
        lines: { select: LINE_SELECT },
      },
    });

    return enrichMovement({ ...movement, hasNegativeStock });
  });
}

// ===========================================================================
// Void (anular)
// Revierte el efecto del movimiento sobre el stock de forma segura.
// ===========================================================================
export async function voidArticleMovement(opts: {
  id: string;
  jewelryId: string;
  userId: string;
  note?: string;
}) {
  const { id, jewelryId, userId } = opts;
  assert(id, "Movimiento inválido.");
  assert(jewelryId, "Tenant inválido.");

  return prisma.$transaction(async (tx) => {
    const movement = await tx.articleMovement.findFirst({
      where: { id, jewelryId },
      select: {
        id: true,
        kind: true,
        status: true,
        sourceType: true,
        warehouseId: true,
        fromWarehouseId: true,
        toWarehouseId: true,
        lines: {
          select: { articleId: true, variantId: true, quantity: true },
        },
      },
    });

    assert(movement, "Movimiento no encontrado.", 404);
    assert(movement!.status !== "VOIDED", "El movimiento ya fue anulado.");
    assert(movement!.status === "CONFIRMED", "Solo se pueden anular movimientos confirmados.");

    // Solo los movimientos manuales se pueden anular desde este módulo
    if (movement!.sourceType !== "MANUAL") {
      const sourceLabels: Record<string, string> = {
        SALE:     "una venta",
        IMPORT:   "una importación masiva",
        PURCHASE: "una orden de compra",
      };
      const label = sourceLabels[movement!.sourceType] ?? movement!.sourceType;
      const e: any = new Error(
        `Este movimiento fue generado por ${label} y no puede anularse manualmente. Anulá desde el módulo de origen.`
      );
      e.status = 409;
      throw e;
    }

    const kind = movement!.kind as Kind;

    // Revertir el efecto en el stock vía motor central
    const lines = movement!.lines.map(l => ({
      articleId: l.articleId,
      variantId: l.variantId,
      quantity:  new Prisma.Decimal(l.quantity.toString()),
    }));

    await reverseMovementImpact(tx, {
      kind,
      jewelryId,
      warehouseId:     movement!.warehouseId     ?? undefined,
      fromWarehouseId: movement!.fromWarehouseId ?? undefined,
      toWarehouseId:   movement!.toWarehouseId   ?? undefined,
      lines,
    });

    const updated = await tx.articleMovement.update({
      where: { id },
      data: {
        status:     "VOIDED",
        voidedAt:   new Date(),
        voidedById: userId || null,
        voidedNote: s(opts.note || ""),
      },
      select: {
        id: true,
        kind: true,
        status: true,
        sourceType: true,
        code: true,
        note: true,
        effectiveAt: true,
        voidedAt: true,
        voidedNote: true,
        createdAt: true,
        warehouse:     { select: { id: true, name: true, code: true } },
        fromWarehouse: { select: { id: true, name: true, code: true } },
        toWarehouse:   { select: { id: true, name: true, code: true } },
        createdBy:     { select: { id: true, name: true, email: true } },
        voidedBy:      { select: { id: true, name: true, email: true } },
        lines: { select: LINE_SELECT },
      },
    });
    return enrichMovement(updated);
  });
}
