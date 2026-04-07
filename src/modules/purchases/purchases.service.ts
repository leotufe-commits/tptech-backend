// src/modules/purchases/purchases.service.ts
import { Prisma } from "@prisma/client";
import { prisma } from "../../lib/prisma.js";
import { computeCostPrice } from "../../lib/article-cost.utils.js";
import { buildBalanceBreakdownFromPrice } from "../../lib/pricing-engine/pricing-engine.balance.js";
import type { BalanceBreakdown } from "../../lib/pricing-engine/pricing-engine.balance.js";
import type { PriceBreakdown } from "../../lib/pricing-engine/pricing-engine.types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function err(msg: string, status = 400): never {
  const e: any = new Error(msg);
  e.status = status;
  throw e;
}

async function nextPurchaseCode(jewelryId: string): Promise<string> {
  const last = await prisma.purchase.findFirst({
    where: { jewelryId },
    orderBy: { createdAt: "desc" },
    select: { code: true },
  });
  let n = 1;
  if (last?.code) {
    const m = last.code.match(/(\d+)$/);
    if (m) n = parseInt(m[1], 10) + 1;
  }
  return `CMP-${String(n).padStart(4, "0")}`;
}

// ---------------------------------------------------------------------------
// Input types
// ---------------------------------------------------------------------------

export type CreatePurchaseLineInput = {
  articleId?: string | null;
  variantId?: string | null;
  quantity: number;
  unitCost: number;
  discountPct?: number;
};

export type CreatePurchaseInput = {
  supplierId: string;
  purchaseDate?: string;
  notes?: string;
  lines: CreatePurchaseLineInput[];
};

export type PaymentComponentInput =
  | {
      componentType: "MONEY";
      amount: number;
      currency?: string;
    }
  | {
      componentType: "METAL";
      metalId: string;
      variantId: string;
      gramsOriginal: number;
      purity: number;
      gramsPure: number;
    };

export type RegisterPaymentInput = {
  purchaseId?: string | null;
  paymentDate?: string;
  note?: string;
  components: PaymentComponentInput[];
};

// ---------------------------------------------------------------------------
// Select shapes
// ---------------------------------------------------------------------------

const PURCHASE_LIST_SELECT = {
  id: true,
  code: true,
  status: true,
  purchaseDate: true,
  subtotal: true,
  discountAmount: true,
  taxAmount: true,
  total: true,
  paidAmount: true,
  notes: true,
  confirmedAt: true,
  cancelledAt: true,
  createdAt: true,
  supplier: { select: { id: true, displayName: true, code: true } },
  createdBy: { select: { id: true, name: true, firstName: true, lastName: true } },
  _count: { select: { lines: true } },
} satisfies Prisma.PurchaseSelect;

const PURCHASE_DETAIL_SELECT = {
  ...PURCHASE_LIST_SELECT,
  supplierSnapshot: true,
  cancelNote: true,
  confirmedById: true,
  cancelledById: true,
  lines: {
    orderBy: { sortOrder: "asc" as const },
    select: {
      id: true,
      articleId: true,
      variantId: true,
      articleName: true,
      variantName: true,
      sku: true,
      barcode: true,
      quantity: true,
      unitCost: true,
      lineTotal: true,
      breakdownSnapshot: true,
      sortOrder: true,
    },
  },
  payments: {
    where: { voidedAt: null },
    orderBy: { paymentDate: "desc" as const },
    select: {
      id: true,
      paymentDate: true,
      note: true,
      createdAt: true,
      components: {
        select: {
          id: true,
          componentType: true,
          amount: true,
          currency: true,
          metalId: true,
          variantId: true,
          gramsOriginal: true,
          purity: true,
          gramsPure: true,
        },
      },
    },
  },
} satisfies Prisma.PurchaseSelect;

// ---------------------------------------------------------------------------
// listPurchases
// ---------------------------------------------------------------------------

export async function listPurchases(
  jewelryId: string,
  opts: {
    supplierId?: string;
    status?: string;
    q?: string;
    skip?: number;
    take?: number;
  } = {}
) {
  const { supplierId, status, q, skip = 0, take = 50 } = opts;

  const where: Prisma.PurchaseWhereInput = {
    jewelryId,
    ...(supplierId ? { supplierId } : {}),
    ...(status ? { status: status as any } : {}),
    ...(q
      ? {
          OR: [
            { code: { contains: q, mode: "insensitive" } },
            { supplier: { displayName: { contains: q, mode: "insensitive" } } },
            { notes: { contains: q, mode: "insensitive" } },
          ],
        }
      : {}),
  };

  const [items, total] = await Promise.all([
    prisma.purchase.findMany({
      where,
      select: PURCHASE_LIST_SELECT,
      orderBy: { purchaseDate: "desc" },
      skip,
      take,
    }),
    prisma.purchase.count({ where }),
  ]);

  return { items, total, skip, take };
}

// ---------------------------------------------------------------------------
// getPurchase
// ---------------------------------------------------------------------------

export async function getPurchase(id: string, jewelryId: string) {
  const purchase = await prisma.purchase.findFirst({
    where: { id, jewelryId },
    select: PURCHASE_DETAIL_SELECT,
  });
  if (!purchase) err("Compra no encontrada.", 404);
  return purchase;
}

// ---------------------------------------------------------------------------
// createPurchase (estado DRAFT)
// ---------------------------------------------------------------------------

export async function createPurchase(
  jewelryId: string,
  userId: string,
  input: CreatePurchaseInput
) {
  const { supplierId, purchaseDate, notes, lines } = input;

  if (!supplierId) err("Proveedor requerido.");
  if (!lines || lines.length === 0) err("Se requiere al menos una línea.");

  // Validar proveedor
  const supplier = await prisma.commercialEntity.findFirst({
    where: { id: supplierId, jewelryId, isSupplier: true, deletedAt: null },
    select: { id: true, displayName: true },
  });
  if (!supplier) err("Proveedor no encontrado o no tiene rol de proveedor.");

  const code = await nextPurchaseCode(jewelryId);

  // Calcular totales en base a las líneas
  let subtotal = 0;
  for (const line of lines) {
    const qty = line.quantity || 0;
    const cost = line.unitCost || 0;
    const disc = line.discountPct || 0;
    subtotal += qty * cost * (1 - disc / 100);
  }

  const total = subtotal; // taxAmount y discountAmount en 0 en creación

  return prisma.purchase.create({
    data: {
      jewelryId,
      code,
      status: "DRAFT",
      supplierId,
      subtotal,
      total,
      purchaseDate: purchaseDate ? new Date(purchaseDate) : new Date(),
      notes: notes || "",
      createdById: userId,
      lines: {
        create: lines.map((line, idx) => ({
          jewelryId,
          articleId: line.articleId ?? null,
          variantId: line.variantId ?? null,
          articleName: "",
          variantName: "",
          quantity: line.quantity,
          unitCost: line.unitCost,
          lineTotal: line.quantity * line.unitCost * (1 - (line.discountPct || 0) / 100),
          sortOrder: idx,
        })),
      },
    },
    select: PURCHASE_DETAIL_SELECT,
  });
}

// ---------------------------------------------------------------------------
// confirmPurchase
// ---------------------------------------------------------------------------

export async function confirmPurchase(
  id: string,
  jewelryId: string,
  userId: string
) {
  const purchase = await prisma.purchase.findFirst({
    where: { id, jewelryId },
    select: {
      id: true,
      status: true,
      supplierId: true,
      total: true,
      code: true,
      lines: {
        select: {
          id: true,
          articleId: true,
          variantId: true,
          quantity: true,
          unitCost: true,
          lineTotal: true,
        },
      },
    },
  });

  if (!purchase) err("Compra no encontrada.", 404);
  if (purchase!.status !== "DRAFT") err("Solo se pueden confirmar compras en estado DRAFT.");

  // Cargar proveedor para snapshot y balanceType
  const supplier = await prisma.commercialEntity.findFirst({
    where: { id: purchase!.supplierId, jewelryId, deletedAt: null },
    select: {
      id: true,
      displayName: true,
      code: true,
      balanceType: true,
      email: true,
      phone: true,
      documentNumber: true,
    },
  });
  if (!supplier) err("Proveedor no encontrado.", 404);

  const supplierSnapshot = {
    id: supplier!.id,
    displayName: supplier!.displayName,
    code: supplier!.code,
    email: supplier!.email,
    phone: supplier!.phone,
    documentNumber: supplier!.documentNumber,
  };

  const isBreakdown = supplier!.balanceType === "BREAKDOWN";

  // ── Calcular totales reales ──────────────────────────────────────────────
  let subtotal = 0;
  for (const line of purchase!.lines) {
    subtotal += parseFloat(line.lineTotal.toString());
  }
  const total = subtotal;

  // ── Calcular breakdowns por línea y preparar snapshots ──────────────────
  type LineWithBreakdown = {
    lineId: string;
    lineTotal: number;
    breakdown: PriceBreakdown | null;
  };

  const linesWithBreakdown: LineWithBreakdown[] = [];

  for (const line of purchase!.lines) {
    let breakdown: PriceBreakdown | null = null;

    if (line.articleId) {
      const article = await prisma.article.findFirst({
        where: { id: line.articleId, jewelryId },
        select: {
          costCalculationMode: true,
          costPrice: true,
          hechuraPrice: true,
          hechuraPriceMode: true,
          mermaPercent: true,
          multiplierBase: true,
          multiplierValue: true,
          multiplierQuantity: true,
          category: { select: { mermaPercent: true } },
          compositions: { select: { variantId: true, grams: true, isBase: true } },
          costComposition: {
            orderBy: { sortOrder: "asc" as const },
            select: {
              type: true,
              label: true,
              quantity: true,
              unitValue: true,
              currencyId: true,
              mermaPercent: true,
              metalVariantId: true,
            },
          },
        },
      });

      if (article) {
        const costResult = await computeCostPrice(jewelryId, {
          costCalculationMode: article.costCalculationMode,
          costPrice: article.costPrice,
          multiplierBase: article.multiplierBase,
          multiplierValue: article.multiplierValue,
          multiplierQuantity: article.multiplierQuantity,
          hechuraPrice: article.hechuraPrice,
          hechuraPriceMode: article.hechuraPriceMode,
          mermaPercent: article.mermaPercent,
          compositions: article.compositions,
          category: article.category,
          costComposition: article.costComposition as any,
        });
        breakdown = costResult.breakdown ?? null;
      }
    }

    linesWithBreakdown.push({
      lineId: line.id,
      lineTotal: parseFloat(line.lineTotal.toString()),
      breakdown,
    });
  }

  // ── Transacción: confirmar compra + crear balance entries ─────────────────
  const updatedPurchase = await prisma.$transaction(async (tx) => {
    // 1. Actualizar purchase
    const updated = await tx.purchase.update({
      where: { id: id },
      data: {
        status: "CONFIRMED",
        subtotal,
        total,
        supplierSnapshot,
        confirmedAt: new Date(),
        confirmedById: userId,
        // Actualizar breakdownSnapshot en cada línea
        lines: {
          update: linesWithBreakdown.map(({ lineId, breakdown }) => ({
            where: { id: lineId },
            data: { breakdownSnapshot: breakdown ? (breakdown as any) : Prisma.JsonNull },
          })),
        },
      },
      select: PURCHASE_DETAIL_SELECT,
    });

    // 2. Crear EntityBalanceEntry según balanceType del proveedor
    if (isBreakdown) {
      // Una entrada por línea con su breakdownSnapshot
      for (const { breakdown, lineTotal } of linesWithBreakdown) {
        let balanceBreakdown: BalanceBreakdown | null = null;

        if (breakdown) {
          balanceBreakdown = buildBalanceBreakdownFromPrice(breakdown);
          // Ajustar hechura: si el breakdown no tiene hechura, usar lineTotal completo
          if (!balanceBreakdown.metals.length && !balanceBreakdown.hechura.amount) {
            balanceBreakdown.hechura.amount = lineTotal;
          }
        } else {
          // Sin breakdown → entrada de hechura pura por el total de la línea
          balanceBreakdown = {
            metals: [],
            hechura: { amount: lineTotal, currency: "BASE" },
          };
        }

        await tx.entityBalanceEntry.create({
          data: {
            entityId: purchase!.supplierId,
            jewelryId,
            role: "SUPPLIER",
            entryType: "PURCHASE_INVOICE",
            amount: new Prisma.Decimal(0),
            currency: "BASE",
            documentRef: purchase!.code,
            notes: `Compra confirmada: ${purchase!.code}`,
            createdBy: userId,
            breakdownSnapshot: balanceBreakdown as any,
          },
        });
      }
    } else {
      // UNIFIED → una sola entrada con el total monetario
      await tx.entityBalanceEntry.create({
        data: {
          entityId: purchase!.supplierId,
          jewelryId,
          role: "SUPPLIER",
          entryType: "PURCHASE_INVOICE",
          amount: new Prisma.Decimal(total.toFixed(2)),
          currency: "BASE",
          documentRef: purchase!.code,
          notes: `Compra confirmada: ${purchase!.code}`,
          createdBy: userId,
          breakdownSnapshot: Prisma.JsonNull,
        },
      });
    }

    return updated;
  });

  return updatedPurchase;
}

// ---------------------------------------------------------------------------
// cancelPurchase
// ---------------------------------------------------------------------------

export async function cancelPurchase(
  id: string,
  jewelryId: string,
  userId: string,
  cancelNote: string
) {
  const purchase = await prisma.purchase.findFirst({
    where: { id, jewelryId },
    select: { id: true, status: true, code: true, supplierId: true },
  });
  if (!purchase) err("Compra no encontrada.", 404);
  if (purchase!.status === "CANCELLED") err("La compra ya está cancelada.");

  const wasConfirmed = purchase!.status !== "DRAFT";

  return prisma.$transaction(async (tx) => {
    // 1. Marcar compra como cancelada
    const updated = await tx.purchase.update({
      where: { id },
      data: {
        status: "CANCELLED",
        cancelledAt: new Date(),
        cancelledById: userId,
        cancelNote: cancelNote || "",
      },
      select: PURCHASE_LIST_SELECT,
    });

    // 2. Si estaba confirmada, revertir balance entries
    if (wasConfirmed) {
      // Anular las entradas originales
      await tx.entityBalanceEntry.updateMany({
        where: {
          entityId: purchase!.supplierId,
          jewelryId,
          documentRef: purchase!.code,
          voidedAt: null,
        },
        data: {
          voidedAt: new Date(),
          voidedBy: userId,
          voidReason: `Compra cancelada: ${cancelNote || "sin nota"}`,
        },
      });
    }

    return updated;
  });
}

// ---------------------------------------------------------------------------
// registerSupplierPayment
//  Registra pago/compensación al proveedor.
//  - purchaseId: opcional (pago vinculado a una compra específica)
//  - components: MONEY y/o METAL
// ---------------------------------------------------------------------------

export async function registerSupplierPayment(
  supplierId: string,
  jewelryId: string,
  userId: string,
  input: RegisterPaymentInput
) {
  const { purchaseId, paymentDate, note, components } = input;

  if (!components || components.length === 0) err("Se requiere al menos un componente de pago.");

  // Validar proveedor
  const supplier = await prisma.commercialEntity.findFirst({
    where: { id: supplierId, jewelryId, isSupplier: true, deletedAt: null },
    select: { id: true, displayName: true, balanceType: true },
  });
  if (!supplier) err("Proveedor no encontrado.", 404);

  // Validar compra si se asocia
  let purchaseCode = "";
  if (purchaseId) {
    const purchase = await prisma.purchase.findFirst({
      where: { id: purchaseId, jewelryId, supplierId },
      select: { id: true, code: true, status: true },
    });
    if (!purchase) err("Compra no encontrada para este proveedor.");
    if (purchase!.status === "DRAFT") err("No se puede pagar una compra en estado DRAFT. Confirmala primero.");
    if (purchase!.status === "CANCELLED") err("No se puede pagar una compra cancelada.");
    purchaseCode = purchase!.code;
  }

  const isBreakdown = supplier!.balanceType === "BREAKDOWN";

  return prisma.$transaction(async (tx) => {
    // Crear cabecera del pago
    const payment = await tx.purchasePayment.create({
      data: {
        jewelryId,
        supplierId,
        purchaseId: purchaseId ?? null,
        paymentDate: paymentDate ? new Date(paymentDate) : new Date(),
        note: note || "",
        createdById: userId,
        components: {
          create: components.map((comp) => {
            if (comp.componentType === "MONEY") {
              return {
                jewelryId,
                componentType: "MONEY" as const,
                amount: new Prisma.Decimal(comp.amount.toFixed(2)),
                currency: (comp as any).currency || "ARS",
              };
            } else {
              const m = comp as Extract<PaymentComponentInput, { componentType: "METAL" }>;
              return {
                jewelryId,
                componentType: "METAL" as const,
                metalId: m.metalId,
                variantId: m.variantId,
                gramsOriginal: m.gramsOriginal,
                purity: m.purity,
                gramsPure: m.gramsPure,
              };
            }
          }),
        },
      },
      select: {
        id: true,
        paymentDate: true,
        note: true,
        components: true,
      },
    });

    // Crear EntityBalanceEntry de signo contrario (reduce deuda)
    const docRef = purchaseCode || `PAY-${payment.id.slice(0, 8)}`;
    const noteText = `Pago a proveedor${purchaseCode ? ` (Compra ${purchaseCode})` : ""}`;

    if (isBreakdown) {
      // Una entrada por componente con el breakdownSnapshot correspondiente
      for (const comp of components) {
        if (comp.componentType === "MONEY") {
          const moneyComp = comp as Extract<PaymentComponentInput, { componentType: "MONEY" }>;
          const balanceBreakdown: BalanceBreakdown = {
            metals: [],
            hechura: { amount: -moneyComp.amount, currency: moneyComp.currency || "ARS" },
          };
          await tx.entityBalanceEntry.create({
            data: {
              entityId: supplierId,
              jewelryId,
              role: "SUPPLIER",
              entryType: "SUPPLIER_PAYMENT",
              amount: new Prisma.Decimal(0),
              currency: "BASE",
              documentRef: docRef,
              notes: noteText,
              createdBy: userId,
              breakdownSnapshot: balanceBreakdown as any,
            },
          });
        } else {
          const metalComp = comp as Extract<PaymentComponentInput, { componentType: "METAL" }>;
          const balanceBreakdown: BalanceBreakdown = {
            metals: [
              {
                metalId: metalComp.metalId,
                variantId: metalComp.variantId,
                gramsOriginal: metalComp.gramsOriginal,
                purity: metalComp.purity,
                gramsPure: -metalComp.gramsPure, // negativo → reduce deuda
              },
            ],
            hechura: { amount: 0, currency: "BASE" },
          };
          await tx.entityBalanceEntry.create({
            data: {
              entityId: supplierId,
              jewelryId,
              role: "SUPPLIER",
              entryType: "SUPPLIER_PAYMENT",
              amount: new Prisma.Decimal(0),
              currency: "BASE",
              documentRef: docRef,
              notes: noteText,
              createdBy: userId,
              breakdownSnapshot: balanceBreakdown as any,
            },
          });
        }
      }
    } else {
      // UNIFIED → sumar todos los componentes monetarios
      let totalAmount = 0;
      for (const comp of components) {
        if (comp.componentType === "MONEY") {
          totalAmount += (comp as any).amount;
        }
        // En UNIFIED, los componentes METAL no reducen saldo monetario
      }
      if (totalAmount > 0) {
        await tx.entityBalanceEntry.create({
          data: {
            entityId: supplierId,
            jewelryId,
            role: "SUPPLIER",
            entryType: "SUPPLIER_PAYMENT",
            amount: new Prisma.Decimal((-totalAmount).toFixed(2)),
            currency: "BASE",
            documentRef: docRef,
            notes: noteText,
            createdBy: userId,
            breakdownSnapshot: Prisma.JsonNull,
          },
        });
      }
    }

    // Actualizar paidAmount de la compra si se asoció
    if (purchaseId) {
      const moneyPaid = components
        .filter((c) => c.componentType === "MONEY")
        .reduce((sum, c) => sum + (c as any).amount, 0);

      if (moneyPaid > 0) {
        const current = await tx.purchase.findFirst({
          where: { id: purchaseId },
          select: { paidAmount: true, total: true },
        });
        if (current) {
          const newPaid = parseFloat(current.paidAmount.toString()) + moneyPaid;
          const total = parseFloat(current.total.toString());
          await tx.purchase.update({
            where: { id: purchaseId },
            data: {
              paidAmount: new Prisma.Decimal(newPaid.toFixed(2)),
              status: newPaid >= total ? "PAID" : "PARTIALLY_PAID",
            },
          });
        }
      }
    }

    return payment;
  });
}

// ---------------------------------------------------------------------------
// registerSupplierMetalReturn
//  Devuelve metal al proveedor (reduce deuda metálica).
// ---------------------------------------------------------------------------

export type MetalReturnInput = {
  paymentDate?: string;
  note?: string;
  metalId: string;
  variantId: string;
  gramsOriginal: number;
  purity: number;
  gramsPure: number;
  purchaseId?: string | null;
};

export async function registerSupplierMetalReturn(
  supplierId: string,
  jewelryId: string,
  userId: string,
  input: MetalReturnInput
) {
  return registerSupplierPayment(supplierId, jewelryId, userId, {
    purchaseId: input.purchaseId ?? null,
    paymentDate: input.paymentDate,
    note: input.note || "Devolución de metal",
    components: [
      {
        componentType: "METAL",
        metalId: input.metalId,
        variantId: input.variantId,
        gramsOriginal: input.gramsOriginal,
        purity: input.purity,
        gramsPure: input.gramsPure,
      },
    ],
  });
}

// ---------------------------------------------------------------------------
// voidSupplierPayment
// ---------------------------------------------------------------------------

export async function voidSupplierPayment(
  paymentId: string,
  jewelryId: string,
  userId: string,
  reason: string
) {
  const payment = await prisma.purchasePayment.findFirst({
    where: { id: paymentId, jewelryId },
    select: { id: true, voidedAt: true, supplierId: true, purchaseId: true, components: true },
  });
  if (!payment) err("Pago no encontrado.", 404);
  if (payment!.voidedAt) err("El pago ya fue anulado.");

  return prisma.$transaction(async (tx) => {
    // Anular el pago
    await tx.purchasePayment.update({
      where: { id: paymentId },
      data: { voidedAt: new Date(), voidedBy: userId, voidReason: reason || "" },
    });

    // Anular las balance entries asociadas
    await tx.entityBalanceEntry.updateMany({
      where: {
        entityId: payment!.supplierId,
        jewelryId,
        entryType: { in: ["SUPPLIER_PAYMENT", "METAL_RETURN"] },
        documentRef: { contains: paymentId.slice(0, 8) },
        voidedAt: null,
      },
      data: {
        voidedAt: new Date(),
        voidedBy: userId,
        voidReason: reason || "",
      },
    });

    // Si tenía compra asociada, restar lo que se revirtió
    if (payment!.purchaseId) {
      const moneyPaid = payment!.components
        .filter((c) => c.componentType === "MONEY")
        .reduce((sum, c) => sum + parseFloat((c.amount ?? 0).toString()), 0);

      if (moneyPaid > 0) {
        const purchase = await tx.purchase.findFirst({
          where: { id: payment!.purchaseId },
          select: { paidAmount: true, total: true, status: true },
        });
        if (purchase && purchase.status !== "CANCELLED") {
          const newPaid = Math.max(0, parseFloat(purchase.paidAmount.toString()) - moneyPaid);
          const total = parseFloat(purchase.total.toString());
          await tx.purchase.update({
            where: { id: payment!.purchaseId },
            data: {
              paidAmount: new Prisma.Decimal(newPaid.toFixed(2)),
              status: newPaid <= 0 ? "CONFIRMED" : newPaid >= total ? "PAID" : "PARTIALLY_PAID",
            },
          });
        }
      }
    }

    return { ok: true };
  });
}

// ---------------------------------------------------------------------------
// applySupplierCredit
//  Aplica un saldo a favor del proveedor (saldo negativo) contra una compra
//  o como ajuste libre. Genera entradas POSITIVAS en el balance que reducen
//  el crédito acumulado.
// ---------------------------------------------------------------------------

export type ApplySupplierCreditInput = {
  purchaseId?: string | null;
  paymentDate?: string;
  note?: string;
  components: PaymentComponentInput[];
};

export async function applySupplierCredit(
  supplierId: string,
  jewelryId: string,
  userId: string,
  input: ApplySupplierCreditInput
) {
  const { purchaseId, paymentDate, note, components } = input;

  if (!components || components.length === 0) err("Se requiere al menos un componente.");

  const supplier = await prisma.commercialEntity.findFirst({
    where: { id: supplierId, jewelryId, isSupplier: true, deletedAt: null },
    select: { id: true, displayName: true, balanceType: true },
  });
  if (!supplier) err("Proveedor no encontrado.", 404);

  let purchaseCode = "";
  if (purchaseId) {
    const purchase = await prisma.purchase.findFirst({
      where: { id: purchaseId, jewelryId, supplierId },
      select: { id: true, code: true, status: true },
    });
    if (!purchase) err("Compra no encontrada para este proveedor.");
    if (purchase!.status === "DRAFT") err("No se puede aplicar saldo a una compra en estado DRAFT.");
    if (purchase!.status === "CANCELLED") err("No se puede aplicar saldo a una compra cancelada.");
    purchaseCode = purchase!.code;
  }

  const isBreakdown = supplier!.balanceType === "BREAKDOWN";

  return prisma.$transaction(async (tx) => {
    const payment = await tx.purchasePayment.create({
      data: {
        jewelryId,
        supplierId,
        purchaseId: purchaseId ?? null,
        paymentDate: paymentDate ? new Date(paymentDate) : new Date(),
        note: note || "Aplicación de saldo a favor",
        createdById: userId,
        components: {
          create: components.map((comp) => {
            if (comp.componentType === "MONEY") {
              return {
                jewelryId,
                componentType: "MONEY" as const,
                amount: new Prisma.Decimal(comp.amount.toFixed(2)),
                currency: (comp as any).currency || "ARS",
              };
            } else {
              const m = comp as Extract<PaymentComponentInput, { componentType: "METAL" }>;
              return {
                jewelryId,
                componentType: "METAL" as const,
                metalId: m.metalId,
                variantId: m.variantId,
                gramsOriginal: m.gramsOriginal,
                purity: m.purity,
                gramsPure: m.gramsPure,
              };
            }
          }),
        },
      },
      select: { id: true, paymentDate: true, note: true, components: true },
    });

    const docRef  = purchaseCode || `CRED-${payment.id.slice(0, 8)}`;
    const noteText = `Saldo a favor aplicado${purchaseCode ? ` (Compra ${purchaseCode})` : ""}`;

    if (isBreakdown) {
      for (const comp of components) {
        if (comp.componentType === "MONEY") {
          const moneyComp = comp as Extract<PaymentComponentInput, { componentType: "MONEY" }>;
          // POSITIVE amount: reduce crédito (saldo a favor → vuelve hacia cero)
          const balanceBreakdown: BalanceBreakdown = {
            metals: [],
            hechura: { amount: moneyComp.amount, currency: moneyComp.currency || "ARS" },
          };
          await tx.entityBalanceEntry.create({
            data: {
              entityId: supplierId,
              jewelryId,
              role: "SUPPLIER",
              entryType: "SUPPLIER_PAYMENT",
              amount: new Prisma.Decimal(0),
              currency: "BASE",
              documentRef: docRef,
              notes: noteText,
              createdBy: userId,
              breakdownSnapshot: balanceBreakdown as any,
            },
          });
        } else {
          const metalComp = comp as Extract<PaymentComponentInput, { componentType: "METAL" }>;
          // POSITIVE gramsPure: añade deuda metálica (consume crédito de metal)
          const balanceBreakdown: BalanceBreakdown = {
            metals: [{
              metalId:       metalComp.metalId,
              variantId:     metalComp.variantId,
              gramsOriginal: metalComp.gramsOriginal,
              purity:        metalComp.purity,
              gramsPure:     metalComp.gramsPure,
            }],
            hechura: { amount: 0, currency: "BASE" },
          };
          await tx.entityBalanceEntry.create({
            data: {
              entityId: supplierId,
              jewelryId,
              role: "SUPPLIER",
              entryType: "SUPPLIER_PAYMENT",
              amount: new Prisma.Decimal(0),
              currency: "BASE",
              documentRef: docRef,
              notes: noteText,
              createdBy: userId,
              breakdownSnapshot: balanceBreakdown as any,
            },
          });
        }
      }
    } else {
      let totalAmount = 0;
      for (const comp of components) {
        if (comp.componentType === "MONEY") totalAmount += (comp as any).amount;
      }
      if (totalAmount > 0) {
        await tx.entityBalanceEntry.create({
          data: {
            entityId: supplierId,
            jewelryId,
            role: "SUPPLIER",
            entryType: "SUPPLIER_PAYMENT",
            amount: new Prisma.Decimal(totalAmount.toFixed(2)),
            currency: "BASE",
            documentRef: docRef,
            notes: noteText,
            createdBy: userId,
            breakdownSnapshot: Prisma.JsonNull,
          },
        });
      }
    }

    // Actualizar paidAmount de la compra si se asoció
    if (purchaseId) {
      const moneyAmount = components
        .filter((c) => c.componentType === "MONEY")
        .reduce((sum, c) => sum + (c as any).amount, 0);

      if (moneyAmount > 0) {
        const current = await tx.purchase.findFirst({
          where: { id: purchaseId },
          select: { paidAmount: true, total: true },
        });
        if (current) {
          const newPaid = parseFloat(current.paidAmount.toString()) + moneyAmount;
          const total   = parseFloat(current.total.toString());
          await tx.purchase.update({
            where: { id: purchaseId },
            data: {
              paidAmount: new Prisma.Decimal(newPaid.toFixed(2)),
              status: newPaid >= total ? "PAID" : "PARTIALLY_PAID",
            },
          });
        }
      }
    }

    return payment;
  });
}

// ---------------------------------------------------------------------------
// listSupplierPayments
// ---------------------------------------------------------------------------

export async function listSupplierPayments(
  supplierId: string,
  jewelryId: string,
  opts: { purchaseId?: string; skip?: number; take?: number } = {}
) {
  const { purchaseId, skip = 0, take = 50 } = opts;

  const where: Prisma.PurchasePaymentWhereInput = {
    supplierId,
    jewelryId,
    ...(purchaseId ? { purchaseId } : {}),
  };

  const [items, total] = await Promise.all([
    prisma.purchasePayment.findMany({
      where,
      select: {
        id: true,
        purchaseId: true,
        paymentDate: true,
        note: true,
        voidedAt: true,
        voidedBy: true,
        voidReason: true,
        createdAt: true,
        createdBy: { select: { id: true, name: true } },
        components: {
          select: {
            id: true,
            componentType: true,
            amount: true,
            currency: true,
            metalId: true,
            variantId: true,
            gramsOriginal: true,
            purity: true,
            gramsPure: true,
          },
        },
      },
      orderBy: { paymentDate: "desc" },
      skip,
      take,
    }),
    prisma.purchasePayment.count({ where }),
  ]);

  return { items, total };
}
